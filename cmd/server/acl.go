package main

import (
	"fmt"
	"strings"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

type aclAction uint8

const (
	aclActionDirect aclAction = iota
	aclActionReject
	aclActionProxy
	aclActionDefault
)

type aclDecision struct {
	action aclAction
	proxy  string
}

type aclDecisionSource uint8

const (
	aclDecisionFromDefault aclDecisionSource = iota
	aclDecisionFromRule
)

type sourcedACLDecision struct {
	decision aclDecision
	source   aclDecisionSource
}

type serverACL struct {
	defaultDecision aclDecision
	rules           []compiledACLRule
}

type compiledACLRule struct {
	matcher  routeRuleSet
	decision aclDecision
}

type normalizedACLRule struct {
	match    []string
	decision aclDecision
}

var defaultServerACLRejectRules = []string{
	"0.0.0.0/32",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::/128",
	"::1/128",
	"fe80::/10",
	"ff00::/8",
	"fc00::/7",
}

func newServerACL(cfg *config.ServerConfig) (*serverACL, error) {
	return compileACLConfig(cfg.ACL, cfg.Outbounds, false)
}

func compileUserACLs(users []config.UserConfig, outbounds map[string]string) (map[string]*serverACL, error) {
	acls := make(map[string]*serverACL)
	for _, user := range users {
		if user.ACL == nil {
			continue
		}
		acl, err := compileACLConfig(user.ACL, outbounds, true)
		if err != nil {
			return nil, fmt.Errorf("user %q acl: %w", user.Name, err)
		}
		acls[user.Name] = acl
	}
	return acls, nil
}

func compileACLConfig(cfg *config.ACLConfig, outbounds map[string]string, allowDefaultFallback bool) (*serverACL, error) {
	if cfg == nil {
		return compileDefaultServerACL()
	}

	acl := &serverACL{}
	decision, err := parseACLDefault(cfg.Default, outbounds, allowDefaultFallback)
	if err != nil {
		return nil, err
	}
	acl.defaultDecision = decision

	normalizedRules := make([]normalizedACLRule, 0, len(cfg.Rules))
	for idx, rule := range cfg.Rules {
		if len(rule.Match) == 0 {
			return nil, fmt.Errorf("acl rule %d has empty match", idx)
		}
		decision, err := parseACLRuleDecision(rule, outbounds)
		if err != nil {
			return nil, fmt.Errorf("acl rule %d: %w", idx, err)
		}
		if len(normalizedRules) > 0 && normalizedRules[len(normalizedRules)-1].decision == decision {
			normalizedRules[len(normalizedRules)-1].match = append(normalizedRules[len(normalizedRules)-1].match, rule.Match...)
			continue
		}
		normalizedRules = append(normalizedRules, normalizedACLRule{
			match:    append([]string(nil), rule.Match...),
			decision: decision,
		})
	}

	for idx, rule := range normalizedRules {
		matcher, err := compileRouteRuleSet(rule.match, "")
		if err != nil {
			return nil, fmt.Errorf("acl rule %d match: %w", idx, err)
		}
		acl.rules = append(acl.rules, compiledACLRule{
			matcher:  matcher,
			decision: rule.decision,
		})
	}
	return acl, nil
}

func compileDefaultServerACL() (*serverACL, error) {
	return &serverACL{
		defaultDecision: aclDecision{action: aclActionDirect},
	}, nil
}

func defaultLocalRejectMatcher() (routeRuleSet, error) {
	matcher, err := compileRouteRuleSet(defaultServerACLRejectRules, "")
	if err != nil {
		return routeRuleSet{}, fmt.Errorf("compile default server acl: %w", err)
	}
	return matcher, nil
}

func parseACLDefault(raw string, outbounds map[string]string, allowDefaultFallback bool) (aclDecision, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "direct") {
		return aclDecision{action: aclActionDirect}, nil
	}
	if strings.EqualFold(value, "default") {
		if allowDefaultFallback {
			return aclDecision{action: aclActionDefault}, nil
		}
		return aclDecision{}, fmt.Errorf("acl default %q is only valid for user acl", raw)
	}
	if strings.EqualFold(value, "reject") {
		return aclDecision{action: aclActionReject}, nil
	}
	if strings.HasPrefix(strings.ToLower(value), "proxy:") {
		return resolveACLProxy(strings.TrimSpace(value[len("proxy:"):]), outbounds)
	}
	if proxy, ok := outbounds[value]; ok {
		return aclDecision{action: aclActionProxy, proxy: strings.TrimSpace(proxy)}, nil
	}
	return aclDecision{}, fmt.Errorf("invalid acl default %q", raw)
}

func parseACLRuleDecision(rule config.ACLRuleConfig, outbounds map[string]string) (aclDecision, error) {
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	switch action {
	case "direct":
		return aclDecision{action: aclActionDirect}, nil
	case "reject":
		return aclDecision{action: aclActionReject}, nil
	case "proxy":
		return resolveACLProxy(rule.Proxy, outbounds)
	default:
		return aclDecision{}, fmt.Errorf("invalid action %q", rule.Action)
	}
}

func resolveACLProxy(raw string, outbounds map[string]string) (aclDecision, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return aclDecision{}, fmt.Errorf("proxy action requires proxy")
	}
	if proxy, ok := outbounds[name]; ok {
		name = strings.TrimSpace(proxy)
	}
	if name == "" {
		return aclDecision{}, fmt.Errorf("proxy %q is empty", raw)
	}
	if !isACLProxyURL(name) {
		return aclDecision{}, fmt.Errorf("unknown proxy %q", raw)
	}
	return aclDecision{action: aclActionProxy, proxy: name}, nil
}

func isACLProxyURL(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "socks5://")
}

func (a *serverACL) decide(req *socks5.Request) aclDecision {
	return a.decideWithSource(req).decision
}

func (a *serverACL) decideWithSource(req *socks5.Request) sourcedACLDecision {
	if a == nil {
		return sourcedACLDecision{decision: aclDecision{action: aclActionDirect}, source: aclDecisionFromDefault}
	}
	target := makeRouteTarget(req)
	for _, rule := range a.rules {
		if rule.matcher.matches(target) {
			return sourcedACLDecision{decision: rule.decision, source: aclDecisionFromRule}
		}
	}
	return sourcedACLDecision{decision: a.defaultDecision, source: aclDecisionFromDefault}
}

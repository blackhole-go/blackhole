package main

import (
	"errors"
	"log"
	"time"

	"blackhole/pkg/constants"
)

type channelResponseReader interface {
	ReadWithTimeout(time.Duration) ([]byte, bool, error)
	Abort() error
}

func (c *Client) handleMuxResponseTimeout(cm *clientMuxConn, err error) {
	if cm == nil || !isMuxResponseTimeoutError(err) {
		return
	}
	count := cm.responseTimeouts.Add(1)
	if count <= maxMuxResponseTimeouts {
		return
	}
	if count == maxMuxResponseTimeouts+1 {
		log.Printf("Closing mux after repeated server response timeouts: server=%s count=%d", muxServerAddr(cm), count)
		c.recordServerDegraded(cm.serverIdentity, muxDropPenalty, "mux closed after repeated server response timeouts")
	}
	cm.intentionalClose.Store(true)
	c.closeMuxAfterResponseTimeout(cm)
}

func (c *Client) closeMuxAfterResponseTimeout(cm *clientMuxConn) {
	if cm == nil {
		return
	}
	cm.intentionalClose.Store(true)
	if cm.mc != nil {
		cm.mc.Close()
	}
}

func isMuxResponseTimeoutError(err error) bool {
	return errors.Is(err, errServerResponseTimeout) || errors.Is(err, errChannelResponseTimeout)
}

func hasServerAck(cm *clientMuxConn) func() bool {
	return func() bool {
		return cm != nil && cm.serverAcked.Load()
	}
}

func readChannelResponseWithTimeout(
	channel channelResponseReader,
	timeout time.Duration,
	hasServerAck func() bool,
	requestStartedAt time.Time,
	onAccepted func(time.Duration),
) ([]byte, bool, error) {
	deadline := requestStartedAt.Add(timeout)
	if requestStartedAt.IsZero() {
		requestStartedAt = time.Now()
		deadline = requestStartedAt.Add(timeout)
	}
	accepted := false
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			channel.Abort()
			acked := hasServerAck != nil && hasServerAck()
			if !acked {
				return nil, false, errServerResponseTimeout
			}
			return nil, true, errChannelResponseTimeout
		}
		data, timedOut, err := channel.ReadWithTimeout(remaining)
		if timedOut {
			channel.Abort()
			acked := hasServerAck != nil && hasServerAck()
			if !acked {
				return nil, false, errServerResponseTimeout
			}
			return nil, true, errChannelResponseTimeout
		}
		if err != nil {
			acked := hasServerAck != nil && hasServerAck()
			return nil, acked, err
		}
		acked := hasServerAck != nil && hasServerAck()
		if len(data) == 1 && data[0] == constants.ChannelResponseAccepted {
			if !accepted {
				accepted = true
				if onAccepted != nil {
					onAccepted(time.Since(requestStartedAt))
				}
			}
			continue
		}
		return data, acked, nil
	}
}

package main

import (
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

func (s *Server) forwardViaReverseRoute(clientChannel *mux.Channel, req *socks5.Request, proxyLevel byte, requestPayload []byte) bool {
	entries := s.reverseRoutes.routes.matchEntries(req)
	if len(entries) == 0 {
		return false
	}

	for _, entry := range entries {
		if entry.mc == nil || entry.mc.IsClosed() {
			s.removeReverseRouteMux(entry.mc, false)
			continue
		}
		if !entry.mc.CanAllocChannel() {
			if reverseMuxTemporarilyFull(entry.mc) {
				continue
			}
			s.removeReverseRouteMux(entry.mc, entry.mc.ActiveChannelCount() == 0)
			continue
		}
		reverseChannel, err := entry.mc.AllocChannel()
		if err != nil {
			if reverseMuxTemporarilyFull(entry.mc) {
				continue
			}
			s.removeReverseRouteMux(entry.mc, entry.mc.ActiveChannelCount() == 0)
			continue
		}
		if err := entry.mc.SendChannelRequestWithProxyLevel(reverseChannel.ID, proxyLevel+1, requestPayload); err != nil {
			log.Printf("Send reverse channel request error: remote=%s error=%v", entry.mc.RemoteName(), err)
			reverseChannel.Close()
			s.removeReverseRouteMux(entry.mc, true)
			continue
		}
		response, timedOut, err := readReverseChannelTargetResponse(reverseChannel, targetConnectTimeout)
		if timedOut || err != nil {
			log.Printf("Read reverse channel response error: remote=%s timeout=%t error=%v", entry.mc.RemoteName(), timedOut, err)
			reverseChannel.Close()
			s.removeReverseRouteMux(entry.mc, true)
			continue
		}
		if len(response) < 1 || response[0] != constants.ChannelResponseOK {
			_ = clientChannel.SendResponse(constants.ChannelResponseFailed)
			reverseChannel.Close()
			clientChannel.Close()
			return true
		}
		if err := clientChannel.SendResponse(constants.ChannelResponseOK); err != nil {
			reverseChannel.Close()
			clientChannel.Close()
			return true
		}
		go relayMuxChannels(mux.NewNetConn(clientChannel), mux.NewNetConn(reverseChannel))
		return true
	}
	return false
}

type reverseChannelResponseReader interface {
	ReadWithTimeout(time.Duration) ([]byte, bool, error)
}

func readReverseChannelTargetResponse(channel reverseChannelResponseReader, timeout time.Duration) ([]byte, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, true, nil
		}
		response, timedOut, err := channel.ReadWithTimeout(remaining)
		if timedOut || err != nil {
			return response, timedOut, err
		}
		if len(response) == 1 && response[0] == constants.ChannelResponseAccepted {
			continue
		}
		return response, false, nil
	}
}

func (s *Server) removeReverseRouteMux(mc *mux.MuxConn, closeMux bool) {
	s.reverseRoutes.routes.removeMux(mc)
	s.reverseRoutes.recv.reset(mc)
	if closeMux && mc != nil {
		_ = mc.Close()
	}
}

func reverseMuxTemporarilyFull(mc *mux.MuxConn) bool {
	snapshot := mc.AllocationSnapshot()
	return !snapshot.Closed &&
		!snapshot.AgeExpired &&
		snapshot.AllocCount < snapshot.MaxAllocCount &&
		snapshot.ActiveCount >= snapshot.MaxActiveCount
}

func relayMuxChannels(left, right *mux.NetConn) {
	var wg sync.WaitGroup
	var abortOnce sync.Once
	var aborted atomic.Bool
	abortBoth := func() {
		abortOnce.Do(func() {
			aborted.Store(true)
			left.Close()
			right.Close()
		})
	}
	copyOne := func(dst, src *mux.NetConn) {
		defer wg.Done()
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(dst, src, buf); err != nil {
			abortBoth()
			return
		}
		if err := dst.CloseWrite(); err != nil {
			abortBoth()
		}
	}
	wg.Add(2)
	go copyOne(left, right)
	go copyOne(right, left)
	wg.Wait()
	if !aborted.Load() {
		_ = left.Finalize()
		_ = right.Finalize()
	}
}

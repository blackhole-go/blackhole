package mux

import (
	"errors"

	"blackhole/pkg/constants"
)

var errInvalidKeepAliveControl = errors.New("invalid keep-alive control message")

func encodeChannelControl(channelID uint8, status byte) []byte {
	return []byte{channelID, status}
}

func encodeChannelRequest(channelID uint8, proxyLevel byte, request []byte) []byte {
	payload := make([]byte, 2+len(request))
	payload[0] = channelID
	payload[1] = proxyLevel
	copy(payload[2:], request)
	return payload
}

func DecodeChannelRequest(payload []byte) (uint8, byte, []byte, bool) {
	if len(payload) < 3 {
		return 0, 0, nil, false
	}
	channelID := payload[0]
	if channelID < uint8(constants.FirstChannelID) {
		return 0, 0, nil, false
	}
	return channelID, payload[1], payload[2:], true
}

func (mc *MuxConn) SendChannelRequest(channelID uint8, request []byte) error {
	return mc.SendChannelRequestWithProxyLevel(channelID, 0, request)
}

func (mc *MuxConn) SendChannelRequestWithProxyLevel(channelID uint8, proxyLevel byte, request []byte) error {
	if channelID < uint8(constants.FirstChannelID) {
		return errors.New("invalid data channel id")
	}
	if len(request) == 0 {
		return errors.New("empty channel request")
	}
	return mc.SendPacket(constants.ChannelRequestChannelID, encodeChannelRequest(channelID, proxyLevel, request))
}

func decodeChannelControl(payload []byte) (uint8, byte, bool) {
	if len(payload) != constants.KeepAlivePayloadSize {
		return 0, 0, false
	}
	channelID := payload[0]
	if channelID < uint8(constants.FirstChannelID) {
		return 0, 0, false
	}
	status := payload[1]
	if status != constants.ChannelResponseOK &&
		status != constants.ChannelResponseFailed &&
		status != constants.ChannelControlFIN &&
		status != constants.ChannelControlClose &&
		status != constants.ChannelResponseAccepted {
		return 0, 0, false
	}
	return channelID, status, true
}

func (mc *MuxConn) sendChannelControl(channelID uint8, status byte) error {
	if channelID < uint8(constants.FirstChannelID) {
		return errors.New("invalid data channel id")
	}
	if status != constants.ChannelResponseOK &&
		status != constants.ChannelResponseFailed &&
		status != constants.ChannelControlFIN &&
		status != constants.ChannelControlClose &&
		status != constants.ChannelResponseAccepted {
		return errors.New("invalid channel control status")
	}
	return mc.SendPacket(constants.KeepAliveChannelID, encodeChannelControl(channelID, status))
}

// SendChannelResponse sends a per-channel status through the keep-alive control channel.
func (mc *MuxConn) SendChannelResponse(channelID uint8, status byte) error {
	if channelID < uint8(constants.FirstChannelID) {
		return errors.New("invalid data channel id")
	}
	if status != constants.ChannelResponseOK &&
		status != constants.ChannelResponseFailed &&
		status != constants.ChannelResponseAccepted {
		return errors.New("invalid channel response status")
	}
	return mc.sendChannelControl(channelID, status)
}

// SendResponse sends this channel's registration or target-setup status through
// the mux control channel.
func (ch *Channel) SendResponse(status byte) error {
	if ch.closedFlag.Load() {
		return errChannelClosed
	}
	return ch.mux.SendChannelResponse(ch.ID, status)
}

func (mc *MuxConn) handleChannelResponse(payload []byte) error {
	channelID, status, ok := decodeChannelControl(payload)
	if !ok {
		return errors.New("invalid channel response message")
	}

	mc.channelsMu.RLock()
	ch := mc.channels[channelID]
	mc.channelsMu.RUnlock()
	if ch == nil {
		return nil
	}
	switch status {
	case constants.ChannelResponseOK, constants.ChannelResponseFailed, constants.ChannelResponseAccepted:
		if err := ch.enqueuePayload([]byte{status}); err != nil {
			if errors.Is(err, errChannelClosed) {
				return nil
			}
			return err
		}
	case constants.ChannelControlFIN:
		ch.receiveFIN()
	case constants.ChannelControlClose:
		ch.receiveClose()
	}
	return nil
}

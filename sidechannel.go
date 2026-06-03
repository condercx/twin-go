package twin

import (
	"sync/atomic"
)

// ChannelType identifies which channel to use.
type ChannelType int

const (
	ChannelPrimary   ChannelType = 0
	ChannelSecondary ChannelType = 1
	ChannelBoth      ChannelType = 2
)

type SideChannel struct {
	enabled  bool
	strategy SideStrategy

	primaryStream   Stream
	secondaryStream Stream

	lossRate     float64
	splitCounter atomic.Uint64
}

type Stream interface {
	Close() error
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

func NewSideChannel(enabled bool, strategy SideStrategy) *SideChannel {
	return &SideChannel{
		enabled:  enabled,
		strategy: strategy,
	}
}

func (sc *SideChannel) SetStreams(primary, secondary Stream) {
	sc.primaryStream = primary
	sc.secondaryStream = secondary
}

func (sc *SideChannel) SetLossRate(rate float64) {
	sc.lossRate = rate
}

// PickChannel returns the channel type to use for a given data length.
func (sc *SideChannel) PickChannel(pktLen int) ChannelType {
	if !sc.enabled || sc.secondaryStream == nil {
		return ChannelPrimary
	}

	switch sc.strategy {
	case SideStrategyMirror:
		// Mirror: send on primary, secondary is for receive diversity
		return ChannelPrimary

	case SideStrategySplit:
		// Split: round-robin between primary and secondary
		val := sc.splitCounter.Add(1)
		if val%2 == 0 {
			return ChannelSecondary
		}
		return ChannelPrimary

	case SideStrategyAuto:
		fallthrough
	default:
		// Auto: small packets go primary, high-loss shifts to secondary
		if pktLen < smallPacketThreshold {
			return ChannelPrimary
		}
		if sc.lossRate > highLossThreshold {
			// High loss: use secondary as well (mirror mode)
			return ChannelPrimary
		}
		if sc.lossRate > mediumLossThreshold {
			// Medium loss: alternate to spread load
			val := sc.splitCounter.Add(1)
			if val%2 == 0 {
				return ChannelSecondary
			}
			return ChannelPrimary
		}
		return ChannelPrimary
	}
}

// PrimaryStream returns the primary stream.
func (sc *SideChannel) PrimaryStream() Stream {
	return sc.primaryStream
}

// SecondaryStream returns the secondary stream, if available.
func (sc *SideChannel) SecondaryStream() Stream {
	if sc.enabled && sc.secondaryStream != nil {
		return sc.secondaryStream
	}
	return nil
}

// Enabled returns whether side channel is enabled.
func (sc *SideChannel) Enabled() bool {
	return sc.enabled
}

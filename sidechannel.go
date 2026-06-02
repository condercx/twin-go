package twin

type SideChannel struct {
	enabled  bool
	strategy SideStrategy

	primaryStream   Stream
	secondaryStream Stream

	lossRate float64
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

func (sc *SideChannel) PickChannel(pktLen int) Stream {
	if !sc.enabled || sc.secondaryStream == nil {
		return sc.primaryStream
	}

	switch sc.strategy {
	case SideStrategyMirror:
		return sc.primaryStream
	case SideStrategySplit:
		return sc.primaryStream
	case SideStrategyAuto:
		fallthrough
	default:
		if pktLen < smallPacketThreshold {
			return sc.primaryStream
		}
		if sc.lossRate > highLossThreshold {
			return sc.primaryStream
		}
		if sc.lossRate > mediumLossThreshold {
			return sc.secondaryStream
		}
		return sc.primaryStream
	}
}

func (sc *SideChannel) MirrorStream() Stream {
	if sc.enabled && sc.secondaryStream != nil {
		return sc.secondaryStream
	}
	return nil
}

func (sc *SideChannel) Close() error {
	return nil
}

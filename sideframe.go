package twin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type SideFrameType byte

const (
	FrameData      SideFrameType = 0x01
	FrameOpenFlow  SideFrameType = 0x02
	FrameCloseFlow SideFrameType = 0x03
	FrameSideData  SideFrameType = 0x04
	FrameHeartbeat SideFrameType = 0x05
)

var (
	ErrShortFrame       = errors.New("side frame too short")
	ErrBadMagic         = errors.New("invalid side magic")
	errUnknownFrameType = errors.New("unknown frame type")
)

const (
	sideFrameMagic     = 0x4E57
	sideFrameHeaderLen = 11
)

type SideFrame struct {
	Type       SideFrameType
	FlowID     uint32
	Payload    []byte
	TargetAddr string
}

func (f *SideFrame) Marshal() ([]byte, error) {
	flowID := f.FlowID
	targetBytes := []byte(f.TargetAddr)
	targetLen := len(targetBytes)
	if targetLen > 65530 {
		return nil, fmt.Errorf("target address too long: %d", targetLen)
	}
	payloadLen := len(f.Payload)
	if payloadLen > 65535 {
		return nil, fmt.Errorf("payload too long: %d", payloadLen)
	}
	totalLen := sideFrameHeaderLen + payloadLen + targetLen
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], sideFrameMagic)
	buf[2] = byte(f.Type)
	binary.BigEndian.PutUint32(buf[3:7], flowID)
	binary.BigEndian.PutUint16(buf[7:9], uint16(payloadLen))
	binary.BigEndian.PutUint16(buf[9:11], uint16(targetLen))

	if payloadLen > 0 {
		copy(buf[11:11+payloadLen], f.Payload)
	}
	if targetLen > 0 {
		copy(buf[11+payloadLen:], targetBytes)
	}
	return buf, nil
}

func (f *SideFrame) Unmarshal(r io.Reader) error {
	header := make([]byte, sideFrameHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	magic := binary.BigEndian.Uint16(header[0:2])
	if magic != sideFrameMagic {
		return ErrBadMagic
	}
	f.Type = SideFrameType(header[2])
	f.FlowID = binary.BigEndian.Uint32(header[3:7])
	payloadLen := int(binary.BigEndian.Uint16(header[7:9]))
	targetLen := int(binary.BigEndian.Uint16(header[9:11]))

	totalBody := payloadLen + targetLen
	if totalBody > 0 {
		body := make([]byte, totalBody)
		if _, err := io.ReadFull(r, body); err != nil {
			return fmt.Errorf("read frame body: %w", err)
		}
		if payloadLen > 0 {
			f.Payload = make([]byte, payloadLen)
			copy(f.Payload, body[:payloadLen])
		}
		if targetLen > 0 {
			f.TargetAddr = string(body[payloadLen:])
		}
	}
	return nil
}

func FrameTypeString(t SideFrameType) string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameOpenFlow:
		return "OPEN_FLOW"
	case FrameCloseFlow:
		return "CLOSE_FLOW"
	case FrameSideData:
		return "SIDE_DATA"
	case FrameHeartbeat:
		return "HEARTBEAT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", byte(t))
	}
}

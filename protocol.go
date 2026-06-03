package twin

import (
	"encoding/binary"
	"errors"
	"io"
)

// udpMessage is the wire format for UDP datagrams.
type udpMessage struct {
	SessionID uint32
	Host      string
	Port      uint16
	MsgID     uint16 // 0 when not fragmented, >0 in fragments
	FragID    uint8  // starts at 0
	FragCount uint8  // 1 when not fragmented
	Data      []byte
}

func (m udpMessage) headerSize() int {
	return 4 + 2 + len(m.Host) + 2 + 2 + 1 + 1 + 2
}

func (m udpMessage) size() int {
	return m.headerSize() + len(m.Data)
}

func (m udpMessage) pack() []byte {
	buf := make([]byte, m.size())
	offset := 0
	binary.BigEndian.PutUint32(buf[offset:], m.SessionID)
	offset += 4
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(m.Host)))
	offset += 2
	copy(buf[offset:], m.Host)
	offset += len(m.Host)
	binary.BigEndian.PutUint16(buf[offset:], m.Port)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], m.MsgID)
	offset += 2
	buf[offset] = m.FragID
	offset++
	buf[offset] = m.FragCount
	offset++
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(m.Data)))
	offset += 2
	copy(buf[offset:], m.Data)
	return buf
}

func (m *udpMessage) unpack(data []byte) error {
	if len(data) < 4+2 {
		return errors.New("udp message too short")
	}
	offset := 0
	m.SessionID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	hostLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+hostLen > len(data) {
		return errors.New("truncated host")
	}
	m.Host = string(data[offset : offset+hostLen])
	offset += hostLen
	if offset+2 > len(data) {
		return errors.New("truncated port")
	}
	m.Port = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+2 > len(data) {
		return errors.New("truncated msg id")
	}
	m.MsgID = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+1 > len(data) {
		return errors.New("truncated frag id")
	}
	m.FragID = data[offset]
	offset++
	if offset+1 > len(data) {
		return errors.New("truncated frag count")
	}
	m.FragCount = data[offset]
	offset++
	if offset+2 > len(data) {
		return errors.New("truncated data len")
	}
	dataLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if offset+dataLen > len(data) {
		return errors.New("truncated data")
	}
	m.Data = make([]byte, dataLen)
	copy(m.Data, data[offset:offset+dataLen])
	return nil
}

func fragUDPMessage(m udpMessage, maxSize int) []udpMessage {
	if m.size() <= maxSize {
		return []udpMessage{m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.headerSize()
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize)
	var frags []udpMessage
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := m
		frag.MsgID = m.MsgID
		if frag.MsgID == 0 {
			frag.MsgID = 1
		}
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = make([]byte, payloadSize)
		copy(frag.Data, fullPayload[off:off+payloadSize])
		frags = append(frags, frag)
		off += payloadSize
		fragID++
	}
	return frags
}

type defragger struct {
	msgID uint16
	frags []*udpMessage
	count uint8
}

func (d *defragger) feed(m udpMessage) *udpMessage {
	if m.FragCount <= 1 {
		return &m
	}
	if int(m.FragID) >= int(m.FragCount) {
		return nil
	}
	if m.MsgID != d.msgID {
		d.msgID = m.MsgID
		d.frags = make([]*udpMessage, m.FragCount)
		d.count = 1
		d.frags[m.FragID] = &m
	} else if d.frags[m.FragID] == nil {
		d.frags[m.FragID] = &m
		d.count++
		if int(d.count) == len(d.frags) {
			var totalLen int
			for _, f := range d.frags {
				totalLen += len(f.Data)
			}
			var data []byte
			if totalLen > 0 {
				data = make([]byte, totalLen)
				off := 0
				for _, f := range d.frags {
					copy(data[off:], f.Data)
					off += len(f.Data)
				}
			}
			m.Data = data
			m.FragID = 0
			m.FragCount = 1
			return &m
		}
	}
	return nil
}

func writeTarget(w io.Writer, target string) error {
	targetBytes := []byte(target)
	lenBuf := []byte{byte(len(targetBytes) >> 8), byte(len(targetBytes))}
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if _, err := w.Write(targetBytes); err != nil {
		return err
	}
	return nil
}

func readTarget(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	targetLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(r, targetBytes); err != nil {
		return "", err
	}
	return string(targetBytes), nil
}

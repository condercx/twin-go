package twin

import (
	"fmt"
	"io"
	"net"
	"sync"
)

type PortalUDPFlow struct {
	targetAddr string
	localConn  *net.UDPConn
	writer     io.Writer
	mu         sync.Mutex
	closed     bool
}

func NewPortalUDPFlow(targetAddr string, w io.Writer) (*PortalUDPFlow, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("dial target: %w", err)
	}
	localConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial target: %w", err)
	}
	return &PortalUDPFlow{
		targetAddr: targetAddr,
		localConn:  localConn,
		writer:     w,
	}, nil
}

func (f *PortalUDPFlow) ReadLoop() {
	buf := make([]byte, DefaultUDPPayloadSize)
	for {
		n, err := f.localConn.Read(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		closed := f.closed
		f.mu.Unlock()
		if closed {
			return
		}
		frame := &SideFrame{
			Type:    FrameData,
			Payload: append([]byte{}, buf[:n]...),
		}
		data, err := frame.Marshal()
		if err != nil {
			continue
		}
		f.writer.Write(data)
	}
}

func (f *PortalUDPFlow) WriteToTarget(data []byte) error {
	_, err := f.localConn.Write(data)
	return err
}

func (f *PortalUDPFlow) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.localConn.Close()
}

type PortalUDPFlowManager struct {
	mu    sync.Mutex
	flows map[udpFlowKey]*PortalUDPFlow
}

type udpFlowKey struct {
	sourceAddr string
	targetAddr string
}

func NewPortalUDPFlowManager() *PortalUDPFlowManager {
	return &PortalUDPFlowManager{
		flows: make(map[udpFlowKey]*PortalUDPFlow),
	}
}

func (m *PortalUDPFlowManager) GetOrCreate(key udpFlowKey, writer io.Writer) (*PortalUDPFlow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.flows[key]; ok {
		return f, nil
	}
	f, err := NewPortalUDPFlow(key.targetAddr, writer)
	if err != nil {
		return nil, err
	}
	m.flows[key] = f
	go f.ReadLoop()
	return f, nil
}

func (m *PortalUDPFlowManager) Remove(key udpFlowKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f, ok := m.flows[key]; ok {
		f.Close()
		delete(m.flows, key)
	}
}

func (m *PortalUDPFlowManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, f := range m.flows {
		f.Close()
		delete(m.flows, k)
	}
}

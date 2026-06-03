package twin

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

type FlowID uint32

type flowIO struct {
	fm     *FlowMux
	fid    FlowID
	dataCh chan []byte
	done   chan struct{}
	once   sync.Once
}

func newFlowIO(fm *FlowMux, fid FlowID) *flowIO {
	return &flowIO{
		fm:     fm,
		fid:    fid,
		dataCh: make(chan []byte, 256),
		done:   make(chan struct{}),
	}
}

func (f *flowIO) Read(p []byte) (int, error) {
	select {
	case data := <-f.dataCh:
		n := copy(p, data)
		if n < len(data) {
			// requeue remainder
			remainder := make([]byte, len(data)-n)
			copy(remainder, data[n:])
			select {
			case f.dataCh <- remainder:
			default:
			}
		}
		return n, nil
	case <-f.done:
		return 0, io.EOF
	}
}

func (f *flowIO) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	sf := SideFrame{
		Type:    FrameData,
		FlowID:  uint32(f.fid),
		Payload: make([]byte, len(p)),
	}
	copy(sf.Payload, p)

	buf, err := sf.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshal data frame: %w", err)
	}

	f.fm.writeMu.Lock()
	_, err = f.fm.stream.Write(buf)
	f.fm.writeMu.Unlock()

	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *flowIO) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.fm.CloseFlow(f.fid)
	})
	return nil
}

type flowEntry struct {
	io     *flowIO
	target string
}

type flowAccept struct {
	FlowID FlowID
	IO     *flowIO
	Target string
}

type FlowMux struct {
	stream    MuxStream
	nextID    atomic.Uint32
	entries   sync.Map
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	acceptCh  chan *flowAccept
	closeOnce sync.Once
	closed    chan struct{}
	writeMu   sync.Mutex
}

type MuxStream interface {
	io.ReadWriteCloser
}

func NewFlowMux(stream MuxStream) *FlowMux {
	ctx, cancel := context.WithCancel(context.Background())
	fm := &FlowMux{
		stream:   stream,
		ctx:      ctx,
		cancel:   cancel,
		acceptCh: make(chan *flowAccept, 64),
		closed:   make(chan struct{}),
	}
	fm.nextID.Store(1)
	return fm
}

func (fm *FlowMux) Start() {
	fm.wg.Add(1)
	go fm.readLoop()
}

func (fm *FlowMux) readLoop() {
	defer fm.wg.Done()
	defer close(fm.acceptCh)

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-fm.closed:
			return
		default:
		}

		var sf SideFrame
		if err := sf.Unmarshal(fm.stream); err != nil {
			return
		}

		switch sf.Type {
		case FrameOpenFlow:
			fid := FlowID(sf.FlowID)
			fio := newFlowIO(fm, fid)
			fm.entries.Store(fid, &flowEntry{io: fio, target: sf.TargetAddr})
			select {
			case fm.acceptCh <- &flowAccept{FlowID: fid, IO: fio, Target: sf.TargetAddr}:
			default:
			}

		case FrameData:
			fid := FlowID(sf.FlowID)
			if v, ok := fm.entries.Load(fid); ok {
				entry := v.(*flowEntry)
				if len(sf.Payload) > 0 {
					select {
					case entry.io.dataCh <- sf.Payload:
					default:
					}
				}
			}

		case FrameCloseFlow:
			fid := FlowID(sf.FlowID)
			if v, ok := fm.entries.LoadAndDelete(fid); ok {
				v.(*flowEntry).io.Close()
			}

		case FrameHeartbeat:
		}
	}
}

func (fm *FlowMux) Accept() (*flowAccept, error) {
	select {
	case fa := <-fm.acceptCh:
		return fa, nil
	case <-fm.ctx.Done():
		return nil, fm.ctx.Err()
	case <-fm.closed:
		return nil, io.EOF
	}
}

func (fm *FlowMux) OpenFlow(target string) (io.ReadWriteCloser, error) {
	fid := FlowID(fm.nextID.Add(1))
	fio := newFlowIO(fm, fid)
	fm.entries.Store(fid, &flowEntry{io: fio, target: target})

	sf := SideFrame{
		Type:       FrameOpenFlow,
		FlowID:     uint32(fid),
		TargetAddr: target,
	}
	data, err := sf.Marshal()
	if err != nil {
		fm.entries.Delete(fid)
		return nil, fmt.Errorf("marshal open flow: %w", err)
	}

	fm.writeMu.Lock()
	_, err = fm.stream.Write(data)
	fm.writeMu.Unlock()

	if err != nil {
		fm.entries.Delete(fid)
		return nil, fmt.Errorf("write open flow: %w", err)
	}
	return fio, nil
}

func (fm *FlowMux) WriteData(fid FlowID, data []byte) error {
	sf := SideFrame{
		Type:    FrameData,
		FlowID:  uint32(fid),
		Payload: data,
	}
	buf, err := sf.Marshal()
	if err != nil {
		return err
	}
	fm.writeMu.Lock()
	_, err = fm.stream.Write(buf)
	fm.writeMu.Unlock()
	return err
}

func (fm *FlowMux) CloseFlow(fid FlowID) error {
	sf := SideFrame{
		Type:   FrameCloseFlow,
		FlowID: uint32(fid),
	}
	buf, err := sf.Marshal()
	if err != nil {
		return err
	}
	fm.writeMu.Lock()
	_, err = fm.stream.Write(buf)
	fm.writeMu.Unlock()

	if err != nil {
		return err
	}
	if v, ok := fm.entries.LoadAndDelete(fid); ok {
		v.(*flowEntry).io.Close()
	}
	return nil
}

func (fm *FlowMux) Close() {
	fm.closeOnce.Do(func() {
		fm.cancel()
		close(fm.closed)
		fm.entries.Range(func(key, value interface{}) bool {
			value.(*flowEntry).io.Close()
			return true
		})
	})
}

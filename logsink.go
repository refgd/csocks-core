package csocks

import "sync"

type LogSink interface {
	OnLog(line string)
}

var (
	sinkMu   sync.RWMutex
	sink     LogSink
	sinkOnce sync.Once
	sinkCh   chan string
)

func SetLogSink(s LogSink) {
	sinkMu.Lock()
	sink = s
	sinkMu.Unlock()

	sinkOnce.Do(func() {
		sinkCh = make(chan string, 512) // 缓冲可按需调大/调小
		go func() {
			for line := range sinkCh {
				sinkMu.RLock()
				cur := sink
				sinkMu.RUnlock()
				if cur != nil {
					func() {
						defer func() { _ = recover() }()
						cur.OnLog(line)
					}()
				}
			}
		}()
	})
}

func emitToSink(line string) {
	sinkMu.RLock()
	hasSink := sink != nil
	sinkMu.RUnlock()
	if !hasSink || sinkCh == nil {
		return
	}

	select {
	case sinkCh <- line:
	default:
		// drop：避免日志风暴阻塞业务
	}
}

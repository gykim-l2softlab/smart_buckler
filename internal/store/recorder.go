package store

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Recorder writes events asynchronously so the request path never waits on disk.
// When the buffer is full, events are dropped and counted rather than blocking.
type Recorder struct {
	store  *Store
	log    *slog.Logger
	events chan Event
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once

	dropped atomic.Uint64

	batchSize     int
	flushInterval time.Duration
}

const (
	defaultBufferSize    = 4096
	defaultBatchSize     = 256
	defaultFlushInterval = 500 * time.Millisecond
	writeTimeout         = 5 * time.Second
)

// NewRecorder starts the background writer. Call Close to flush and stop it.
func NewRecorder(s *Store, log *slog.Logger) *Recorder {
	return newRecorder(s, log, defaultBufferSize, defaultBatchSize, defaultFlushInterval)
}

func newRecorder(s *Store, log *slog.Logger, bufferSize, batchSize int, flushInterval time.Duration) *Recorder {
	r := &Recorder{
		store:         s,
		log:           log,
		events:        make(chan Event, bufferSize),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		batchSize:     batchSize,
		flushInterval: flushInterval,
	}
	go r.run()
	return r
}

// Record enqueues an event without blocking. It is safe to call after Close;
// the event is dropped.
func (r *Recorder) Record(e Event) {
	select {
	case <-r.stop:
		r.dropped.Add(1)
		return
	default:
	}
	select {
	case r.events <- e:
	default:
		r.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped so far.
func (r *Recorder) Dropped() uint64 { return r.dropped.Load() }

// Close stops accepting events, flushes the buffer and waits for the writer.
func (r *Recorder) Close(ctx context.Context) error {
	r.once.Do(func() { close(r.stop) })
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Recorder) run() {
	defer close(r.done)
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, r.batchSize)
	var reportedDrops uint64

	flush := func() {
		if d := r.dropped.Load(); d != reportedDrops {
			r.log.Warn("event buffer full, events dropped", "dropped_total", d)
			reportedDrops = d
		}
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		defer cancel()
		if err := r.store.InsertEvents(ctx, batch); err != nil {
			r.log.Error("write events", "err", err, "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-r.events:
			batch = append(batch, e)
			if len(batch) >= r.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-r.stop:
			for {
				select {
				case e := <-r.events:
					batch = append(batch, e)
					if len(batch) >= r.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

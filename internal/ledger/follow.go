package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Watching the ledger comes in two shapes, because there are two kinds of
// watcher.
//
// A process that holds the Store — the server, feeding its panel — takes
// Subscribe and is handed every entry as it is recorded, with no polling and
// no parsing.
//
// A second process — "nhcx-adapter ledger follow" in another terminal, while
// the server writes — cannot see that channel, so Follow tails the day files
// the way tail -f does. It is deliberately dumb: no inotify, no fsnotify
// dependency, no shared state with the writer. A stat and a read of whatever
// is new, a few times a second, is enough for a ledger that writes one short
// line per message, and it behaves the same on every platform this ships to.

// maxSubscriberLag is how many entries a subscriber may fall behind before
// its channel is left to drop them. A slow reader must not be able to block
// Record — the message has already crossed the adapter, and a stalled
// browser tab is not a reason to hold up the one writing it down.
const maxSubscriberLag = 256

// Subscribe returns a channel carrying every entry recorded from now on, and
// a function that stops the subscription and closes the channel. The channel
// is buffered; entries that arrive while it is full are dropped rather than
// delaying the writer, so a subscriber that must not miss anything should
// re-read the ledger rather than trust the stream alone.
//
// Cancel is safe to call more than once and must be called, or the
// subscription leaks for the life of the Store.
func (s *Store) Subscribe() (<-chan Summary, func()) {
	ch := make(chan Summary, maxSubscriberLag)
	s.submu.Lock()
	if s.subs == nil {
		s.subs = map[chan Summary]struct{}{}
	}
	s.subs[ch] = struct{}{}
	s.submu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.submu.Lock()
			delete(s.subs, ch)
			s.submu.Unlock()
			close(ch)
		})
	}
}

// publish hands a recorded summary to the subscribers, never blocking.
func (s *Store) publish(sm Summary) {
	s.submu.RLock()
	defer s.submu.RUnlock()
	for ch := range s.subs {
		select {
		case ch <- sm:
		default: // subscriber is behind; drop rather than stall the writer
		}
	}
}

// Match reports whether a summary passes the query's filters. Limit and
// Before are about paging a listing and are ignored here.
func (q Query) Match(sm Summary) bool { return q.matches(&sm) }

// FollowOptions configure Follow.
type FollowOptions struct {
	// After suppresses entries whose id is not greater than this one — the
	// id of the last entry the caller has already shown, so a listing
	// printed before following is not repeated by it.
	After string
	// Query filters what is delivered. Limit and Before are ignored.
	Query Query
	// Interval is how often the day files are checked. Default 400ms.
	Interval time.Duration
}

// Follow calls fn for each entry appended to the ledger from now on, until
// ctx is cancelled (whereupon it returns ctx.Err()).
//
// It reads the day files rather than the in-memory index, so it sees what
// another process writes — which is the point: the server records, this
// follows. Entries already on disk when Follow starts are not replayed; list
// them first if you want them, and pass the newest id as After.
//
// fn is called on Follow's goroutine, in the order the entries were written.
func (s *Store) Follow(ctx context.Context, o FollowOptions, fn func(Summary)) error {
	if o.Interval <= 0 {
		o.Interval = 400 * time.Millisecond
	}
	f := &follower{dir: s.dir, after: o.After, query: o.Query, offsets: map[string]int64{}}
	// Start at the end of what is already written, so nothing is replayed.
	f.scan(nil)

	ticker := time.NewTicker(o.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			f.scan(fn)
		}
	}
}

// follower is the tail state: how far into each day's index.jsonl we have
// read, and the id floor below which an entry is old news.
type follower struct {
	dir     string
	after   string
	query   Query
	offsets map[string]int64 // day folder → bytes consumed
	start   string           // earliest day folder worth reading
}

// scan reads what is new in every day file and delivers it. A nil fn means
// "take note of where the files end", which is how Follow starts.
func (f *follower) scan(fn func(Summary)) {
	days, err := os.ReadDir(f.dir)
	if err != nil {
		return // the directory can appear later; try again next tick
	}
	names := make([]string, 0, len(days))
	for _, d := range days {
		if !d.IsDir() || !isDayFolder(d.Name()) {
			continue
		}
		// Only today and later — an id carries its day, so a folder older
		// than the one we started in can hold nothing newer than After.
		if f.start == "" || d.Name() >= f.start {
			names = append(names, d.Name())
		}
	}
	// Ascending, so a message written just after midnight UTC is delivered
	// after the ones before it rather than before them.
	sort.Strings(names)
	if f.start == "" && len(names) > 0 {
		f.start = names[len(names)-1] // the newest day present when we began
		names = names[len(names)-1:]
	}
	// A day folder that has gone (retention, or "ledger clear") should not
	// keep an offset that would suppress a fresh file of the same name.
	present := make(map[string]bool, len(names))
	for _, day := range names {
		present[day] = true
	}
	for day := range f.offsets {
		if !present[day] {
			delete(f.offsets, day)
		}
	}
	for _, day := range names {
		f.readDay(day, fn)
	}
}

// maxCatchUp bounds one read, so a follower that was paused (SIGSTOP, a
// laptop lid) catches up over several ticks instead of one huge allocation.
const maxCatchUp = 4 << 20

func (f *follower) readDay(day string, fn func(Summary)) {
	path := filepath.Join(f.dir, day, "index.jsonl")
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	off := f.offsets[day]
	// A file shorter than our offset was truncated or replaced — "ledger
	// clear" while following. Start it again from the top.
	if fi.Size() < off {
		off = 0
	}
	if fi.Size() == off {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	if _, err := file.Seek(off, io.SeekStart); err != nil {
		return
	}
	buf, err := io.ReadAll(io.LimitReader(file, maxCatchUp))
	if err != nil || len(buf) == 0 {
		return
	}
	// Consume whole lines only. The writer appends one line per message in a
	// single write, but a reader that arrives mid-write would otherwise take
	// half a record as a parse failure and skip it for good.
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		return
	}
	f.offsets[day] = off + int64(end) + 1
	if fn == nil {
		return
	}
	for _, line := range bytes.Split(buf[:end], []byte("\n")) {
		var sm Summary
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &sm) != nil || sm.ID == "" {
			continue
		}
		if f.after != "" && sm.ID <= f.after {
			continue
		}
		f.after = sm.ID
		if f.query.Match(sm) {
			fn(sm)
		}
	}
}

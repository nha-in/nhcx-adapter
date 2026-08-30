// Package ledger keeps a record of every FHIR message that crossed the
// gateway — headers, bundle, and what happened to it — so an operator or an
// agent can answer "what did we send, what came back, and where does this
// correlation id stand?" without a database.
//
// Storage is plain files: one JSON document per message under
// <dir>/<yyyy-mm-dd>/<id>.json, plus a per-day index.jsonl of summaries
// that is all the process reads at startup. Ids are time-ordered, so
// "newest first" and "before id" pagination need no sorting on disk.
package ledger

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nhcx-gateway/internal/nhcx"
)

// Direction of a message relative to this gateway.
const (
	Out = "out" // our system → NHCX
	In  = "in"  // NHCX → our system
)

// Outcome values.
const (
	StatusAccepted       = "accepted"        // out: NHCX answered 2xx
	StatusRejected       = "rejected"        // out: NHCX answered 4xx/5xx; in: we refused it (undecryptable, wrong recipient)
	StatusFailed         = "failed"          // out: never reached NHCX (no certificate, no token, unreachable)
	StatusDelivered      = "delivered"       // in: callback accepted it
	StatusDeliveryFailed = "delivery_failed" // in: callback refused or unreachable (NHCX will retry)
)

// Entry is one message, complete.
type Entry struct {
	ID        string    `json:"id"`
	Direction string    `json:"direction"`
	CreatedAt time.Time `json:"created_at"`

	Path   string `json:"path"`             // v1/preauth/on_submit
	Entity string `json:"entity"`           // preauth
	Action string `json:"action"`           // on_submit
	Kind   string `json:"kind"`             // request | response
	Format string `json:"format,omitempty"` // fhir | protocol | json (inbound payload kind)

	Sender        string `json:"sender,omitempty"`
	Recipient     string `json:"recipient,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	APICallID     string `json:"api_call_id,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
	WorkflowID    string `json:"workflow_id,omitempty"`
	HCXStatus     string `json:"hcx_status,omitempty"` // x-hcx-status

	Status     string `json:"status"`
	Error      *Error `json:"error,omitempty"`
	Redelivery bool   `json:"redelivery,omitempty"` // in: same api_call_id seen before
	DurationMs int64  `json:"duration_ms"`

	// Outcome on the far side: NHCX's answer (out) or the callback's (in).
	Peer *Peer `json:"peer,omitempty"`

	Headers map[string]any  `json:"headers,omitempty"` // full protected header set
	FHIR    json.RawMessage `json:"fhir,omitempty"`    // the bundle (omitted when storeBodies is off)
	Summary *FHIRSummary    `json:"fhir_summary,omitempty"`
}

// Error is a typed failure.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Peer is what the other side answered.
type Peer struct {
	URL        string          `json:"url"`
	StatusCode int             `json:"status_code"`
	Response   json.RawMessage `json:"response,omitempty"`
}

// FHIRSummary is the shape of a bundle at a glance, for listings and for
// agents that should not have to parse the whole bundle to pick a thread.
type FHIRSummary struct {
	ResourceType  string         `json:"resource_type"`
	BundleType    string         `json:"bundle_type,omitempty"`
	Entries       int            `json:"entries"`
	ResourceTypes map[string]int `json:"resource_types,omitempty"`
	Focus         string         `json:"focus,omitempty"`      // main resource, e.g. Claim/abc
	Identifier    string         `json:"identifier,omitempty"` // its first identifier value
	Patient       string         `json:"patient,omitempty"`
	Outcome       string         `json:"outcome,omitempty"` // ClaimResponse.outcome etc.
}

// Summary is an Entry without its bodies — what listings carry.
type Summary struct {
	ID            string       `json:"id"`
	Direction     string       `json:"direction"`
	CreatedAt     time.Time    `json:"created_at"`
	Path          string       `json:"path"`
	Entity        string       `json:"entity"`
	Action        string       `json:"action"`
	Kind          string       `json:"kind"`
	Format        string       `json:"format,omitempty"`
	Sender        string       `json:"sender,omitempty"`
	Recipient     string       `json:"recipient,omitempty"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	APICallID     string       `json:"api_call_id,omitempty"`
	WorkflowID    string       `json:"workflow_id,omitempty"`
	HCXStatus     string       `json:"hcx_status,omitempty"`
	Status        string       `json:"status"`
	Error         *Error       `json:"error,omitempty"`
	Redelivery    bool         `json:"redelivery,omitempty"`
	PeerStatus    int          `json:"peer_status,omitempty"`
	DurationMs    int64        `json:"duration_ms"`
	Summary       *FHIRSummary `json:"fhir_summary,omitempty"`
}

func (e *Entry) summary() Summary {
	s := Summary{
		ID: e.ID, Direction: e.Direction, CreatedAt: e.CreatedAt, Path: e.Path, Entity: e.Entity, Action: e.Action,
		Kind: e.Kind, Format: e.Format, Sender: e.Sender, Recipient: e.Recipient, CorrelationID: e.CorrelationID,
		APICallID: e.APICallID, WorkflowID: e.WorkflowID, HCXStatus: e.HCXStatus, Status: e.Status, Error: e.Error,
		Redelivery: e.Redelivery, DurationMs: e.DurationMs, Summary: e.Summary,
	}
	if e.Peer != nil {
		s.PeerStatus = e.Peer.StatusCode
	}
	return s
}

// Options configure a Store.
type Options struct {
	Dir           string
	RetentionDays int
	StoreBodies   bool
}

// Store is the ledger.
type Store struct {
	dir         string
	retention   time.Duration
	storeBodies bool

	mu      sync.RWMutex
	entries map[string]*Summary
	ids     []string            // ascending
	byCorr  map[string][]string // correlation id → ids (ascending)
	seen    map[string]bool     // direction + api_call_id
	idDay   string              // day code the counter belongs to
	idSeq   uint64              // last sequence issued on that day
}

// ErrNotFound is returned by Get for an unknown id.
var ErrNotFound = errors.New("ledger: entry not found")

// Open creates the directory if needed and loads the summaries.
func Open(o Options) (*Store, error) {
	if o.Dir == "" {
		return nil, errors.New("ledger: dir is required")
	}
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	s := &Store{
		dir: o.Dir, storeBodies: o.StoreBodies,
		entries: map[string]*Summary{}, byCorr: map[string][]string{}, seen: map[string]bool{},
	}
	if o.RetentionDays > 0 {
		s.retention = time.Duration(o.RetentionDays) * 24 * time.Hour
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	days, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	for _, d := range days {
		if !d.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(s.dir, d.Name(), "index.jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		for sc.Scan() {
			var sm Summary
			if json.Unmarshal(sc.Bytes(), &sm) == nil && sm.ID != "" {
				s.add(&sm)
			}
		}
		f.Close()
	}
	sort.Strings(s.ids)
	for k := range s.byCorr {
		sort.Strings(s.byCorr[k])
	}
	return nil
}

// add indexes a summary (caller holds the lock or is single-threaded).
func (s *Store) add(sm *Summary) {
	if _, dup := s.entries[sm.ID]; dup {
		return
	}
	s.entries[sm.ID] = sm
	s.ids = append(s.ids, sm.ID)
	if sm.CorrelationID != "" {
		s.byCorr[sm.CorrelationID] = append(s.byCorr[sm.CorrelationID], sm.ID)
	}
	if sm.APICallID != "" {
		s.seen[sm.Direction+":"+sm.APICallID] = true
	}
}

// Ledger ids are eight characters: four for the UTC date as YYMMDD, four for
// a counter that restarts each day — 7UMV0001 is the first message of
// 2026-08-31. Short enough to read out, compare by eye and paste into a
// filter, where the old 32-character timestamp-plus-random ids were not.
//
// The alphabet is base32 over 0-9A-V, chosen because its ASCII order matches
// its numeric order: a fixed-width id therefore sorts chronologically as a
// plain string, which is what the ledger's "everything after X" queries and
// the ascending ids slice rely on. RFC 4648's A-Z2-7 alphabet does not have
// that property — '2' sorts before 'A' — and would have broken the ordering
// silently.
const (
	idAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	idDayWidth = 4 // YYMMDD needs 18 bits; 3 chars hold only 15
	idSeqWidth = 4 // 32^4 = 1,048,576 messages in one day
	idWidth    = idDayWidth + idSeqWidth
)

// encodeID renders v in base32, left-padded to width.
func encodeID(v uint64, width int) string {
	b := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		b[i] = idAlphabet[v&31]
		v >>= 5
	}
	return string(b)
}

// decodeID reads a fixed-width base32 field back. Anything outside the
// alphabet makes it zero, so a stray file name cannot poison the counter.
func decodeID(s string) uint64 {
	var v uint64
	for i := 0; i < len(s); i++ {
		j := strings.IndexByte(idAlphabet, s[i])
		if j < 0 {
			return 0
		}
		v = v<<5 | uint64(j)
	}
	return v
}

// dayCode is the UTC date as YYMMDD, encoded. It rises with the calendar, so
// ids stay ordered across a date boundary.
func dayCode(t time.Time) string {
	u := t.UTC()
	return encodeID(uint64(u.Year()%100*10000+int(u.Month())*100+u.Day()), idDayWidth)
}

// nextID issues the next id for t. The caller holds s.mu.
//
// On the first message of a day — including the first after a restart — the
// counter picks up from the highest id already on record for that date, so a
// restart cannot hand out an id that is already a file on disk.
func (s *Store) nextID(t time.Time) string {
	day := dayCode(t)
	if day != s.idDay {
		s.idDay, s.idSeq = day, s.highestSeq(day)
	}
	s.idSeq++
	return day + encodeID(s.idSeq, idSeqWidth)
}

// highestSeq is the largest counter already issued on that day. Ids from
// before this scheme are a different length and are ignored.
func (s *Store) highestSeq(day string) uint64 {
	var high uint64
	for _, id := range s.ids {
		if len(id) != idWidth || id[:idDayWidth] != day {
			continue
		}
		if v := decodeID(id[idDayWidth:]); v > high {
			high = v
		}
	}
	return high
}

// Record stores an entry. Missing id, timestamp, entity/action/kind and
// FHIR summary are filled in.
func (s *Store) Record(e *Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	if e.ID == "" {
		s.mu.Lock()
		e.ID = s.nextID(e.CreatedAt)
		s.mu.Unlock()
	}
	e.Path = nhcx.CleanPath(e.Path)
	if e.Entity == "" {
		e.Entity = nhcx.EntityType(e.Path)
	}
	if e.Action == "" {
		segs := strings.Split(e.Path, "/")
		e.Action = segs[len(segs)-1]
	}
	if e.Kind == "" {
		if nhcx.IsResponsePath(e.Path) {
			e.Kind = "response"
		} else {
			e.Kind = "request"
		}
	}
	if e.Summary == nil && len(e.FHIR) > 0 {
		e.Summary = Summarize(e.FHIR)
	}
	if !s.storeBodies {
		e.FHIR = nil
		if e.Peer != nil {
			e.Peer.Response = nil
		}
	}

	day := e.CreatedAt.UTC().Format("2006-01-02")
	dir := filepath.Join(s.dir, day)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	body, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("ledger: encode: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, e.ID+".json"), body, 0o640); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}

	sm := e.summary()
	line, _ := json.Marshal(sm)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, err := os.OpenFile(filepath.Join(dir, "index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	_, werr := idx.Write(append(line, '\n'))
	idx.Close()
	if werr != nil {
		return fmt.Errorf("ledger: %w", werr)
	}
	s.add(&sm)
	// ids are appended in time order except across a clock step; keep sorted.
	if n := len(s.ids); n > 1 && s.ids[n-1] < s.ids[n-2] {
		sort.Strings(s.ids)
	}
	if list := s.byCorr[sm.CorrelationID]; len(list) > 1 && list[len(list)-1] < list[len(list)-2] {
		sort.Strings(list)
	}
	return nil
}

// Get reads one full entry.
func (s *Store) Get(id string) (*Entry, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	day, ok := idDay(id)
	if !ok {
		return nil, ErrNotFound
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, day, id+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("ledger: %w", err)
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("ledger: %s is corrupt: %w", id, err)
	}
	return &e, nil
}

func validID(id string) bool {
	_, ok := idDay(id)
	return ok
}

// idDay is the day folder an id lives in, as "2006-01-02".
//
// Two schemes are read. Current ids are eight base32 characters whose first
// four are the date; ids written before that are a UTC timestamp beginning
// YYYYMMDD. A ledger written by an older build stays readable — the records
// are the point of keeping one, and rewriting history to suit a new id format
// would be a strange thing to do to an audit trail.
func idDay(id string) (string, bool) {
	if strings.ContainsAny(id, "/\\") {
		return "", false
	}
	if len(id) == idWidth {
		for i := 0; i < idWidth; i++ {
			if strings.IndexByte(idAlphabet, id[i]) < 0 {
				return "", false
			}
		}
		v := decodeID(id[:idDayWidth])
		yy, mm, dd := v/10000, v/100%100, v%100
		if mm < 1 || mm > 12 || dd < 1 || dd > 31 {
			return "", false
		}
		return fmt.Sprintf("20%02d-%02d-%02d", yy, mm, dd), true
	}
	if len(id) >= 24 {
		for _, c := range id[:8] {
			if c < '0' || c > '9' {
				return "", false
			}
		}
		return id[:4] + "-" + id[4:6] + "-" + id[6:8], true
	}
	return "", false
}

// Query filters a listing. Zero values mean "any".
type Query struct {
	Direction     string
	Entity        string
	Kind          string
	Status        string
	Sender        string
	Recipient     string
	Participant   string // sender or recipient
	CorrelationID string
	WorkflowID    string
	Since, Until  time.Time
	Before        string // id: page older than this
	Limit         int
}

// List returns summaries newest first.
func (s *Store) List(q Query) []Summary {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.ids
	if q.CorrelationID != "" {
		ids = s.byCorr[q.CorrelationID]
	}
	out := make([]Summary, 0, min(q.Limit, len(ids)))
	for i := len(ids) - 1; i >= 0 && len(out) < q.Limit; i-- {
		id := ids[i]
		if q.Before != "" && id >= q.Before {
			continue
		}
		sm := s.entries[id]
		if sm == nil || !q.matches(sm) {
			continue
		}
		out = append(out, *sm)
	}
	return out
}

func (q Query) matches(sm *Summary) bool {
	switch {
	case q.Direction != "" && sm.Direction != q.Direction,
		q.Entity != "" && sm.Entity != q.Entity,
		q.Kind != "" && sm.Kind != q.Kind,
		q.Status != "" && sm.Status != q.Status,
		q.Sender != "" && !nhcx.SameCode(sm.Sender, q.Sender),
		q.Recipient != "" && !nhcx.SameCode(sm.Recipient, q.Recipient),
		q.Participant != "" && !nhcx.SameCode(sm.Sender, q.Participant) && !nhcx.SameCode(sm.Recipient, q.Participant),
		q.WorkflowID != "" && sm.WorkflowID != q.WorkflowID,
		!q.Since.IsZero() && sm.CreatedAt.Before(q.Since),
		!q.Until.IsZero() && sm.CreatedAt.After(q.Until):
		return false
	}
	return true
}

// Thread is every message sharing a correlation id, with a derived state.
type Thread struct {
	CorrelationID string    `json:"correlation_id"`
	Entity        string    `json:"entity,omitempty"`
	WorkflowID    string    `json:"workflow_id,omitempty"`
	Counterparty  string    `json:"counterparty,omitempty"`
	Role          string    `json:"role,omitempty"` // initiator | responder
	State         string    `json:"state"`          // see Thread states
	Started       time.Time `json:"started"`
	Updated       time.Time `json:"updated"`
	Messages      []Summary `json:"messages"`
}

// Thread states, derived from the messages seen so far.
const (
	ThreadAwaitingResponse    = "awaiting_response"     // we sent a request, nothing came back yet
	ThreadAwaitingOurResponse = "awaiting_our_response" // a request reached us, we have not answered
	ThreadCompleted           = "completed"             // a response closed the exchange
	ThreadPartial             = "partial"               // response.partial received, more to come
	ThreadError               = "error"                 // response.error, a rejection, or a failed send/delivery
	ThreadUnknown             = "unknown"
)

// Thread assembles the exchange for a correlation id (nil when unseen).
func (s *Store) Thread(correlationID string, self string) *Thread {
	s.mu.RLock()
	ids := s.byCorr[correlationID]
	msgs := make([]Summary, 0, len(ids))
	for _, id := range ids {
		if sm := s.entries[id]; sm != nil {
			msgs = append(msgs, *sm)
		}
	}
	s.mu.RUnlock()
	if len(msgs) == 0 {
		return nil
	}
	t := &Thread{CorrelationID: correlationID, Messages: msgs, Started: msgs[0].CreatedAt, Updated: msgs[len(msgs)-1].CreatedAt}
	first := msgs[0]
	t.Entity, t.WorkflowID = first.Entity, first.WorkflowID
	if first.Direction == Out {
		t.Role, t.Counterparty = "initiator", first.Recipient
	} else {
		t.Role, t.Counterparty = "responder", first.Sender
	}
	if first.Kind == "response" { // thread started mid-way (ledger enabled late)
		if first.Direction == Out {
			t.Role, t.Counterparty = "responder", first.Recipient
		} else {
			t.Role, t.Counterparty = "initiator", first.Sender
		}
	}
	t.State = deriveState(msgs)
	return t
}

func deriveState(msgs []Summary) string {
	state := ThreadUnknown
	for _, m := range msgs {
		switch {
		case m.Status == StatusFailed, m.Status == StatusRejected, m.Status == StatusDeliveryFailed && m.Kind == "response":
			state = ThreadError
			continue
		case m.Format == "protocol" || strings.Contains(m.HCXStatus, "error"):
			state = ThreadError
			continue
		}
		switch m.Kind {
		case "request":
			if m.Direction == Out {
				state = ThreadAwaitingResponse
			} else {
				state = ThreadAwaitingOurResponse
			}
		case "response":
			if m.HCXStatus == "response.partial" {
				state = ThreadPartial
			} else {
				state = ThreadCompleted
			}
		}
	}
	return state
}

// LastInboundRequest finds the newest inbound request of an entity from a
// participant (optionally within a workflow) — the exchange an outbound
// "on_" response answers when the caller did not say.
func (s *Store) LastInboundRequest(entity, from, workflowID string) *Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.ids) - 1; i >= 0; i-- {
		sm := s.entries[s.ids[i]]
		if sm == nil || sm.Direction != In || sm.Kind != "request" || sm.Entity != entity || sm.CorrelationID == "" {
			continue
		}
		if from != "" && !nhcx.SameCode(sm.Sender, from) {
			continue
		}
		if workflowID != "" && sm.WorkflowID != workflowID {
			continue
		}
		return sm
	}
	return nil
}

// Seen reports whether a message with this api_call_id was already recorded
// in that direction — an inbound redelivery, or a duplicate send.
func (s *Store) Seen(direction, apiCallID string) bool {
	if apiCallID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seen[direction+":"+apiCallID]
}

// Stats counts what the ledger holds.
type Stats struct {
	Total       int            `json:"total"`
	ByDirection map[string]int `json:"by_direction"`
	ByStatus    map[string]int `json:"by_status"`
	ByEntity    map[string]int `json:"by_entity"`
	Threads     int            `json:"threads"`
	Oldest      *time.Time     `json:"oldest,omitempty"`
	Newest      *time.Time     `json:"newest,omitempty"`
	Last24h     int            `json:"last_24h"`
	Dir         string         `json:"dir"`
}

// Stats summarises the ledger.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{ByDirection: map[string]int{}, ByStatus: map[string]int{}, ByEntity: map[string]int{}, Threads: len(s.byCorr), Dir: s.dir}
	cut := time.Now().Add(-24 * time.Hour)
	for _, id := range s.ids {
		sm := s.entries[id]
		st.Total++
		st.ByDirection[sm.Direction]++
		st.ByStatus[sm.Status]++
		st.ByEntity[sm.Entity]++
		if sm.CreatedAt.After(cut) {
			st.Last24h++
		}
	}
	if len(s.ids) > 0 {
		o, n := s.entries[s.ids[0]].CreatedAt, s.entries[s.ids[len(s.ids)-1]].CreatedAt
		st.Oldest, st.Newest = &o, &n
	}
	return st
}

// Sweep deletes day directories older than the retention period and drops
// their entries from the index. Returns how many entries went.
// Clear removes every recorded message and empties the in-memory index. It
// returns how many messages went.
//
// Only day folders are touched — directories named like 2026-08-31, holding
// the records this store wrote. A ledger directory that has been pointed at
// something else by a mistaken config is not this function's to empty, and
// "clear the ledger" should never become "delete whatever is in that path".
func (s *Store) Clear() (int, error) {
	days, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("ledger: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	var failed error
	for _, d := range days {
		if !d.IsDir() || !isDayFolder(d.Name()) {
			continue
		}
		for _, id := range s.ids {
			if day, ok := idDay(id); ok && day == d.Name() {
				removed++
			}
		}
		if err := os.RemoveAll(filepath.Join(s.dir, d.Name())); err != nil && failed == nil {
			failed = fmt.Errorf("ledger: %w", err)
		}
	}

	s.entries = map[string]*Summary{}
	s.ids = nil
	s.byCorr = map[string][]string{}
	s.seen = map[string]bool{}
	// The counter is derived from what is on record, and there is nothing on
	// record now, so the next message starts the day again at 0001.
	s.idDay, s.idSeq = "", 0
	return removed, failed
}

// isDayFolder reports whether name looks like a YYYY-MM-DD ledger folder.
func isDayFolder(name string) bool {
	if len(name) != 10 || name[4] != '-' || name[7] != '-' {
		return false
	}
	for i, c := range name {
		if i == 4 || i == 7 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *Store) Sweep(now time.Time) int {
	if s.retention == 0 {
		return 0
	}
	cutoff := now.Add(-s.retention).UTC().Format("2006-01-02")
	days, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	removed := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range days {
		if !d.IsDir() || len(d.Name()) != 10 || d.Name() >= cutoff {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.dir, d.Name())); err != nil {
			continue
		}
		kept := s.ids[:0]
		for _, id := range s.ids {
			if day, ok := idDay(id); ok && day == d.Name() {
				sm := s.entries[id]
				delete(s.entries, id)
				if sm != nil {
					if sm.APICallID != "" {
						delete(s.seen, sm.Direction+":"+sm.APICallID)
					}
					if sm.CorrelationID != "" {
						s.byCorr[sm.CorrelationID] = without(s.byCorr[sm.CorrelationID], id)
						if len(s.byCorr[sm.CorrelationID]) == 0 {
							delete(s.byCorr, sm.CorrelationID)
						}
					}
				}
				removed++
				continue
			}
			kept = append(kept, id)
		}
		s.ids = kept
	}
	return removed
}

func without(list []string, id string) []string {
	out := list[:0]
	for _, v := range list {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// Summarize describes a bundle at a glance.
func Summarize(raw json.RawMessage) *FHIRSummary {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	rt, _ := doc["resourceType"].(string)
	if rt == "" {
		return nil
	}
	sm := &FHIRSummary{ResourceType: rt, ResourceTypes: map[string]int{}}
	resources := []map[string]any{doc}
	if rt == "Bundle" {
		sm.BundleType, _ = doc["type"].(string)
		entries, _ := doc["entry"].([]any)
		sm.Entries = len(entries)
		resources = resources[:0]
		for _, e := range entries {
			if em, ok := e.(map[string]any); ok {
				if res, ok := em["resource"].(map[string]any); ok {
					resources = append(resources, res)
				}
			}
		}
	}
	priority := map[string]int{
		"Claim": 1, "ClaimResponse": 1, "CoverageEligibilityRequest": 1, "CoverageEligibilityResponse": 1,
		"Communication": 1, "CommunicationRequest": 1, "PaymentNotice": 1, "PaymentReconciliation": 1,
		"Task": 1, "InsurancePlan": 1, "Composition": 3,
	}
	best := 99
	for _, r := range resources {
		t, _ := r["resourceType"].(string)
		if t == "" {
			continue
		}
		sm.ResourceTypes[t]++
		if t == "Patient" && sm.Patient == "" {
			sm.Patient = resourceRef(r)
		}
		p, ok := priority[t]
		if !ok {
			p = 2
		}
		if p < best {
			best = p
			sm.Focus = resourceRef(r)
			sm.Identifier = firstIdentifier(r)
			sm.Outcome, _ = r["outcome"].(string)
			if sm.Outcome == "" {
				if st, ok := r["status"].(string); ok && strings.HasSuffix(t, "Response") {
					sm.Outcome = st
				}
			}
		}
	}
	if len(sm.ResourceTypes) == 0 {
		sm.ResourceTypes = nil
	}
	return sm
}

func resourceRef(r map[string]any) string {
	t, _ := r["resourceType"].(string)
	id, _ := r["id"].(string)
	if id == "" {
		return t
	}
	return t + "/" + id
}

func firstIdentifier(r map[string]any) string {
	ids, _ := r["identifier"].([]any)
	for _, i := range ids {
		if m, ok := i.(map[string]any); ok {
			if v, _ := m["value"].(string); v != "" {
				return v
			}
		}
	}
	return ""
}

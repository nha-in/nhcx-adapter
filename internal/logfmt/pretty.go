// Package logfmt renders slog records for people: one coloured line per
// message crossing the adapter, compact lines for everything else. The JSON
// handler stays the choice for log collectors; this one is for terminals.
package logfmt

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nhcx-adapter/internal/style"
)

// Handler is a slog.Handler producing readable, coloured lines.
type Handler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Leveler
	attrs []slog.Attr
	group string
}

// New returns a handler writing to w at the given level.
func New(w io.Writer, level slog.Leveler) *Handler {
	return &Handler{mu: &sync.Mutex{}, w: w, level: level}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &c
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	c := *h
	if c.group != "" {
		c.group += "."
	}
	c.group += name
	return &c
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	kv := map[string]string{}
	var order []string
	add := func(a slog.Attr) {
		a.Value = a.Value.Resolve()
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		if _, seen := kv[key]; !seen {
			order = append(order, key)
		}
		kv[key] = a.Value.String()
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })

	var line string
	switch r.Message {
	case "outbound":
		line = message(r.Time, kv, "out", kv["recipient"], kv["nhcx"]).Render()
	case "inbound":
		line = message(r.Time, kv, "in", kv["sender"], kv["callback"]).Render()
	default:
		line = generic(r, kv, order)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line+"\n")
	return err
}

func stamp(t time.Time) string { return style.Dim(t.Format("15:04:05.000")) }

// Column widths for the traffic lines. Every message crossing the adapter
// prints the same fields in the same places, so a screenful can be read down
// a column — "which of these failed", "which took a second" — instead of
// being parsed line by line. A field wider than its column pushes that one
// line out rather than being truncated: the value matters more than the grid.
//
// Padding is computed from the plain text, never the styled string, because
// the colour escapes are bytes with no width and would skew every column.
const (
	colID     = 8  // 7UMV0007 (omitted when the ledger is off)
	colPath   = 31 // v1/coverageeligibility/on_check
	colPeer   = 15 // 1000004805@hcx
	colStatus = 15 // delivery_failed
	colPeerHT = 13 // callback 200
	colTook   = 7  // 2210ms
	colFlags  = 21 // protocol  redelivery
)

// pad appends styled and the spaces that bring plain up to width.
func pad(styled, plain string, width int) string {
	if n := width - utf8.RuneCountInString(plain); n > 0 {
		return styled + strings.Repeat(" ", n)
	}
	return styled
}

// Message is one message crossing the adapter, in the fields a traffic line
// prints. It is the shape both callers have: the server, which logs each
// message as it happens, and "ledger follow", which reads them back off the
// ledger — so both print the same line and an operator learns one format.
type Message struct {
	Time          time.Time
	ID            string // ledger id, when the message was recorded
	Direction     string // "out" (we sent it) or "in" (it arrived)
	Path          string // v1/preauth/on_submit
	Peer          string // the counterparty's code
	Status        string // accepted, delivered, rejected, failed, delivery_failed
	PeerStatus    int    // HTTP status from NHCX (out) or the callback (in)
	TookMs        int64
	Format        string // fhir | protocol | json — flagged when it is not fhir
	Redelivery    bool
	Error         string // error code, when there was one
	CorrelationID string
}

// message builds a Message from a traffic log record.
func message(t time.Time, kv map[string]string, direction, peer, peerStatus string) Message {
	code, _ := strconv.Atoi(peerStatus)
	took, _ := strconv.ParseInt(kv["took_ms"], 10, 64)
	return Message{
		Time: t, ID: kv["ledger_id"], Direction: direction, Path: kv["path"], Peer: peer, Status: kv["status"],
		PeerStatus: code, TookMs: took, Format: kv["kind"], Redelivery: kv["redelivery"] == "true",
		Error: kv["error"], CorrelationID: kv["correlation_id"],
	}
}

// Render draws the message as one coloured line, in columns:
//
//	12:01:05.123 7UMV0007 ▲ OUT v1/preauth/submit    → 1000004805@hcx  accepted         nhcx 202      412ms                        0f4c2b2e-…
//	12:01:05.480 7UMV0008 ▼ IN  v1/preauth/on_submit ← 1000004805@hcx  delivered        callback 200  480ms   redelivery           0f4c2b2e-…
//
// The ledger id comes second because it is what every follow-up command
// takes — "ledger show 7UMV0007", "panel → open" — and a line you cannot
// trace back to a record is a line you have to go looking for.
func (m Message) Render() string {
	tag, arrow, peerLabel, paint := "▲ OUT", "→", "nhcx", style.Out
	if m.Direction == "in" {
		tag, arrow, peerLabel, paint = "▼ IN ", "←", "callback", style.In
	}
	var st string
	switch m.Status {
	case "accepted", "delivered":
		st = style.Good(m.Status)
	case "rejected", "failed", "delivery_failed":
		st = style.Bad(m.Status)
	default:
		st = style.Warn(m.Status)
	}
	peer := m.Peer
	if peer == "" {
		peer = "?"
	}

	var b strings.Builder
	b.WriteString(stamp(m.Time) + " ")
	if m.ID != "" {
		b.WriteString(pad(style.Dim(m.ID), m.ID, colID) + " ")
	}
	// The tag is the direction and only the direction — outbound and inbound
	// keep their own colour even on a failure, because the status column two
	// along is already red and colouring both says the same thing twice while
	// losing the one thing the tag is for.
	b.WriteString(paint(tag))
	b.WriteString(" ")
	b.WriteString(pad(style.Key(m.Path), m.Path, colPath))
	b.WriteString(" " + style.Dim(arrow) + " ")
	b.WriteString(pad(style.Key(peer), peer, colPeer))
	b.WriteString(" ")
	b.WriteString(pad(st, m.Status, colStatus))
	b.WriteString(" ")

	// The peer's HTTP answer: NHCX's status going out, the callback's coming in.
	peerHT, peerHTPlain := "", ""
	if m.PeerStatus != 0 {
		code := strconv.Itoa(m.PeerStatus)
		peerHTPlain = peerLabel + " " + code
		peerHT = style.Dim(peerLabel) + " " + code
	}
	b.WriteString(pad(peerHT, peerHTPlain, colPeerHT))
	b.WriteString(" ")

	took, tookPlain := "", ""
	if m.TookMs > 0 {
		tookPlain = strconv.FormatInt(m.TookMs, 10) + "ms"
		took = style.Dim(tookPlain)
	}
	b.WriteString(pad(took, tookPlain, colTook))
	b.WriteString(" ")

	// Flags share one column so the correlation id starts in the same place
	// whether a message was flagged or not.
	var flags, flagsPlain []string
	if m.Format != "" && m.Format != "fhir" {
		flags, flagsPlain = append(flags, style.Warn(m.Format)), append(flagsPlain, m.Format)
	}
	if m.Redelivery {
		flags, flagsPlain = append(flags, style.Warn("redelivery")), append(flagsPlain, "redelivery")
	}
	if m.Error != "" {
		flags, flagsPlain = append(flags, style.Bad(m.Error)), append(flagsPlain, m.Error)
	}
	b.WriteString(pad(strings.Join(flags, " "), strings.Join(flagsPlain, " "), colFlags))

	// The correlation id is the handle for everything else — the thread in
	// the ledger, the counterparty's records — so it is shown in full, last.
	// It needs no label: it is the only bare uuid on the line.
	if m.CorrelationID != "" {
		b.WriteString(" " + m.CorrelationID)
	}
	return strings.TrimRight(b.String(), " ")
}

// generic renders any other record: time, coloured level, message, then
// key=value pairs in the order they were given (env first, since the logger
// carries it).
func generic(r slog.Record, kv map[string]string, order []string) string {
	var lvl string
	switch {
	case r.Level >= slog.LevelError:
		lvl = style.Bad("ERR ")
	case r.Level >= slog.LevelWarn:
		lvl = style.Warn("WARN")
	case r.Level >= slog.LevelInfo:
		lvl = style.Good("INFO")
	default:
		lvl = style.Dim("DBG ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s", stamp(r.Time), lvl, r.Message)
	sort.SliceStable(order, func(i, j int) bool { return order[i] == "env" && order[j] != "env" })
	for _, k := range order {
		if k == "env" {
			continue // the banner already says so; every line repeating it is noise
		}
		v := kv[k]
		if strings.ContainsAny(v, " \t\"") {
			v = fmt.Sprintf("%q", v)
		}
		switch k {
		case "error", "cause":
			fmt.Fprintf(&b, " %s=%s", style.Dim(k), style.Bad(v))
		default:
			fmt.Fprintf(&b, " %s=%s", style.Dim(k), v)
		}
	}
	return b.String()
}

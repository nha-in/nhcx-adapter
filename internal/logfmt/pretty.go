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
		line = traffic(r, kv, "▲ OUT", "→", kv["recipient"], "nhcx", style.Out)
	case "inbound":
		line = traffic(r, kv, "▼ IN ", "←", kv["sender"], "callback", style.In)
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

// traffic renders one message line, in columns:
//
//	12:01:05.123 ▲ OUT v1/preauth/submit             → 1000004805@hcx  accepted         nhcx 202      412ms                        0f4c2b2e-…
//	12:01:05.480 ▼ IN  v1/preauth/on_submit          ← 1000004805@hcx  delivered        callback 200  480ms   redelivery           0f4c2b2e-…
func traffic(r slog.Record, kv map[string]string, tag, arrow, peer, peerLabel string,
	paint func(string) string) string {
	status := kv["status"]
	var st string
	switch status {
	case "accepted", "delivered":
		st = style.Good(status)
	case "rejected", "failed", "delivery_failed":
		st = style.Bad(status)
	default:
		st = style.Warn(status)
	}
	if peer == "" {
		peer = "?"
	}

	var b strings.Builder
	b.WriteString(stamp(r.Time) + " ")
	// The tag is the direction and only the direction — outbound and inbound
	// keep their own colour even on a failure, because the status column two
	// along is already red and colouring both says the same thing twice while
	// losing the one thing the tag is for.
	b.WriteString(paint(tag))
	b.WriteString(" ")
	b.WriteString(pad(style.Key(kv["path"]), kv["path"], colPath))
	b.WriteString(" " + style.Dim(arrow) + " ")
	b.WriteString(pad(style.Key(peer), peer, colPeer))
	b.WriteString(" ")
	b.WriteString(pad(st, status, colStatus))
	b.WriteString(" ")

	// The peer's HTTP answer: NHCX's status going out, the callback's coming in.
	peerHT, peerHTPlain := "", ""
	if code := kv[peerLabel]; code != "" && code != "0" {
		peerHTPlain = peerLabel + " " + code
		peerHT = style.Dim(peerLabel) + " " + code
	}
	b.WriteString(pad(peerHT, peerHTPlain, colPeerHT))
	b.WriteString(" ")

	took, tookPlain := "", ""
	if ms := kv["took_ms"]; ms != "" {
		tookPlain = ms + "ms"
		took = style.Dim(tookPlain)
	}
	b.WriteString(pad(took, tookPlain, colTook))
	b.WriteString(" ")

	// Flags share one column so the correlation id starts in the same place
	// whether a message was flagged or not.
	var flags, flagsPlain []string
	if kv["kind"] != "" && kv["kind"] != "fhir" {
		flags, flagsPlain = append(flags, style.Warn(kv["kind"])), append(flagsPlain, kv["kind"])
	}
	if kv["redelivery"] == "true" {
		flags, flagsPlain = append(flags, style.Warn("redelivery")), append(flagsPlain, "redelivery")
	}
	if e := kv["error"]; e != "" {
		flags, flagsPlain = append(flags, style.Bad(e)), append(flagsPlain, e)
	}
	b.WriteString(pad(strings.Join(flags, " "), strings.Join(flagsPlain, " "), colFlags))

	// The correlation id is the handle for everything else — the thread in
	// the ledger, the counterparty's records — so it is shown in full, last.
	// It needs no label: it is the only bare uuid on the line.
	if c := kv["correlation_id"]; c != "" {
		b.WriteString(" " + c)
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

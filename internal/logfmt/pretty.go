// Package logfmt renders slog records for people: one coloured line per
// message crossing the gateway, compact lines for everything else. The JSON
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

	"nhcx-gateway/internal/style"
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
		line = traffic(r, kv, "▲ OUT", "→", kv["recipient"], "nhcx")
	case "inbound":
		line = traffic(r, kv, "▼ IN ", "←", kv["sender"], "callback")
	default:
		line = generic(r, kv, order)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line+"\n")
	return err
}

func stamp(t time.Time) string { return style.Dim(t.Format("15:04:05.000")) }

// traffic renders one message line:
//
//	12:01:05.123 ▲ OUT v1/preauth/submit → 1000004805@hcx  accepted  nhcx 202  412ms  corr 0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11
func traffic(r slog.Record, kv map[string]string, tag, arrow, peer, peerLabel string) string {
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
	if r.Level >= slog.LevelWarn {
		b.WriteString(style.Bad(tag))
	} else {
		b.WriteString(style.Brand(tag))
	}
	fmt.Fprintf(&b, " %s %s %s  %s", style.Key(kv["path"]), style.Dim(arrow), style.Key(peer), st)
	if code := kv[peerLabel]; code != "" && code != "0" {
		fmt.Fprintf(&b, "  %s %s", style.Dim(peerLabel), code)
	}
	if ms := kv["took_ms"]; ms != "" {
		b.WriteString("  " + style.Dim(ms+"ms"))
	}
	if kv["kind"] != "" && kv["kind"] != "fhir" {
		b.WriteString("  " + style.Warn(kv["kind"]))
	}
	if kv["redelivery"] == "true" {
		b.WriteString("  " + style.Warn("redelivery"))
	}
	if e := kv["error"]; e != "" {
		b.WriteString("  " + style.Bad(e))
	}
	// The correlation id is the handle for everything else — the thread in
	// the ledger, the counterparty's records — so it is shown in full, last.
	if c := kv["correlation_id"]; c != "" {
		b.WriteString("  " + style.Dim("corr ") + c)
	}
	return b.String()
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

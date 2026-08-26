// Package gateway is the adapter itself: it turns an integrator's FHIR
// bundle into an encrypted NHCX call, and an encrypted NHCX callback into a
// plain delivery to the integrator. Both directions are synchronous and
// stateless — the only state is the session token and certificate cache in
// the abdm client.
package gateway

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nhcx-gateway/internal/abdm"
	"nhcx-gateway/internal/config"
	"nhcx-gateway/internal/keys"
	"nhcx-gateway/internal/ledger"
	"nhcx-gateway/internal/nhcx"
)

// Gateway holds one participant's identity and its ABDM client.
type Gateway struct {
	cfg    *config.Config
	abdm   *abdm.Client
	priv   *rsa.PrivateKey
	log    *slog.Logger
	http   *http.Client
	ledger *ledger.Store // nil when disabled
}

// New parses the participant's private key and builds the gateway.
func New(cfg *config.Config, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}
	priv, err := keys.ParsePrivateKey(cfg.Participant.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("participant.privateKey: %w", err)
	}
	g := &Gateway{
		cfg:  cfg,
		abdm: abdm.New(cfg, &priv.PublicKey, logger),
		priv: priv,
		log:  logger,
		http: &http.Client{Timeout: time.Duration(cfg.Callback.TimeoutSeconds) * time.Second},
	}
	if cfg.LedgerEnabled() {
		store, err := ledger.Open(ledger.Options{Dir: cfg.Resolve(cfg.Ledger.Dir), RetentionDays: cfg.Ledger.RetentionDays, StoreBodies: cfg.LedgerStoresBodies()})
		if err != nil {
			return nil, err
		}
		g.ledger = store
	}
	return g, nil
}

// Ledger returns the message ledger, or nil when disabled.
func (g *Gateway) Ledger() *ledger.Store { return g.ledger }

// record writes to the ledger when enabled; a ledger failure is logged, it
// never fails the message.
func (g *Gateway) record(e *ledger.Entry) {
	if g.ledger == nil {
		return
	}
	if err := g.ledger.Record(e); err != nil {
		g.log.Error("ledger write failed", "error", err.Error(), "direction", e.Direction, "path", e.Path)
	}
}

// ABDM exposes the client for the token / cert CLI commands and probes.
func (g *Gateway) ABDM() *abdm.Client { return g.abdm }

// Config returns the loaded configuration.
func (g *Gateway) Config() *config.Config { return g.cfg }

// SetHTTPClients swaps the transports used for ABDM and callback calls (tests).
func (g *Gateway) SetHTTPClients(upstream, callback *http.Client) {
	if upstream != nil {
		g.abdm.SetHTTPClient(upstream)
	}
	if callback != nil {
		g.http = callback
	}
}

// ------------------------------------------------------------- outbound ----

// OutboundRequest is one message to send through NHCX.
type OutboundRequest struct {
	// Path is the NHCX API path, e.g. "v1/preauth/submit".
	Path string
	// Headers are the caller's x-hcx-* values; missing ones are completed.
	Headers map[string]any
	// FHIR is the bundle, as JSON.
	FHIR json.RawMessage
}

// OutboundResult reports what went on the wire and what the gateway said.
type OutboundResult struct {
	Path          string          `json:"path"`
	URL           string          `json:"url"`
	Headers       map[string]any  `json:"headers"`
	GatewayStatus int             `json:"gateway_status"`
	Response      json.RawMessage `json:"response"`
	DurationMs    int64           `json:"duration_ms"`
	LedgerID      string          `json:"ledger_id,omitempty"`
}

// Accepted reports whether NHCX took the message (2xx; 202 in practice).
func (r *OutboundResult) Accepted() bool { return r.GatewayStatus >= 200 && r.GatewayStatus < 300 }

// Send encrypts the bundle for its recipient and posts it to NHCX. Every
// attempt — accepted, rejected by NHCX, or failed before dispatch — is
// recorded in the ledger.
func (g *Gateway) Send(ctx context.Context, req OutboundRequest) (*OutboundResult, error) {
	path := nhcx.CleanPath(req.Path)
	if path == "" {
		return nil, &abdm.Error{Code: "NO_PATH", Message: "NHCX API path is required (e.g. v1/preauth/submit)"}
	}
	if len(bytes.TrimSpace(req.FHIR)) == 0 || !json.Valid(req.FHIR) {
		return nil, &abdm.Error{Code: "INVALID_PAYLOAD", Message: "fhir payload must be a JSON value"}
	}

	// A response must carry the request's correlation id. When the caller
	// did not supply one, the ledger knows which inbound request this
	// answers: the newest one of the same entity from that participant.
	if g.ledger != nil && nhcx.IsResponsePath(path) && !nhcx.IsID(nhcx.GetString(req.Headers, nhcx.HdrCorrelationID)) {
		if prev := g.ledger.LastInboundRequest(nhcx.EntityType(path), nhcx.GetString(req.Headers, nhcx.HdrRecipient), nhcx.GetString(req.Headers, nhcx.HdrWorkflowID)); prev != nil {
			if req.Headers == nil {
				req.Headers = map[string]any{}
			}
			req.Headers[nhcx.HdrCorrelationID] = prev.CorrelationID
			if prev.WorkflowID != "" && nhcx.GetString(req.Headers, nhcx.HdrWorkflowID) == "" {
				req.Headers[nhcx.HdrWorkflowID] = prev.WorkflowID
			}
		}
	}

	headers := nhcx.BuildProtectedHeaders(req.Headers, path)
	if nhcx.GetString(headers, nhcx.HdrSender) == "" {
		headers[nhcx.HdrSender] = g.cfg.Participant.ParticipantID
	}
	recipient := nhcx.GetString(headers, nhcx.HdrRecipient)

	start := time.Now()
	entry := &ledger.Entry{
		Direction: ledger.Out, CreatedAt: start, Path: path,
		Sender: nhcx.GetString(headers, nhcx.HdrSender), Recipient: recipient,
		CorrelationID: nhcx.GetString(headers, nhcx.HdrCorrelationID), APICallID: nhcx.GetString(headers, nhcx.HdrAPICallID),
		RequestID: nhcx.GetString(headers, nhcx.HdrRequestID), WorkflowID: nhcx.GetString(headers, nhcx.HdrWorkflowID),
		HCXStatus: nhcx.GetString(headers, nhcx.HdrStatus), Headers: headers, FHIR: compactJSON(req.FHIR), Format: "fhir",
	}
	fail := func(err error) (*OutboundResult, error) {
		e := abdm.AsError(err)
		entry.Status, entry.Error, entry.DurationMs = ledger.StatusFailed, &ledger.Error{Code: e.Code, Message: e.Message}, time.Since(start).Milliseconds()
		g.record(entry)
		g.log.Warn("outbound", "path", path, "sender", entry.Sender, "recipient", recipient, "status", ledger.StatusFailed,
			"error", e.Code, "took_ms", entry.DurationMs, "correlation_id", entry.CorrelationID, "ledger_id", entry.ID)
		return nil, err
	}

	if recipient == "" {
		return fail(&abdm.Error{Code: "NO_RECIPIENT", Message: nhcx.HdrRecipient + " is required"})
	}
	pub, _, err := g.abdm.Certificate(ctx, recipient)
	if err != nil {
		return fail(err)
	}
	compact, err := nhcx.Encrypt(entry.FHIR, pub, headers)
	if err != nil {
		return fail(&abdm.Error{Code: "ENCRYPT_ERROR", Message: "encrypt payload", Err: err})
	}
	res, err := g.abdm.Dispatch(ctx, path, compact)
	if err != nil {
		return fail(err)
	}

	entry.DurationMs = res.Duration.Milliseconds()
	entry.Peer = &ledger.Peer{URL: res.URL, StatusCode: res.StatusCode, Response: res.Body}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		entry.Status = ledger.StatusAccepted
	} else {
		entry.Status = ledger.StatusRejected
		entry.Error = &ledger.Error{Code: fmt.Sprintf("GATEWAY_HTTP_%d", res.StatusCode), Message: "NHCX did not accept the message"}
	}
	g.record(entry)

	level := slog.LevelInfo
	if entry.Status != ledger.StatusAccepted {
		level = slog.LevelWarn
	}
	g.log.Log(ctx, level, "outbound",
		"path", path, "sender", headers[nhcx.HdrSender], "recipient", recipient, "status", entry.Status,
		"nhcx", res.StatusCode, "took_ms", res.Duration.Milliseconds(),
		"correlation_id", headers[nhcx.HdrCorrelationID], "api_call_id", headers[nhcx.HdrAPICallID], "ledger_id", entry.ID)
	return &OutboundResult{
		Path: path, URL: res.URL, Headers: headers,
		GatewayStatus: res.StatusCode, Response: res.Body, DurationMs: res.Duration.Milliseconds(), LedgerID: entry.ID,
	}, nil
}

// ParseOutboundBody reads the integrator's envelope. Two shapes are accepted:
//
//	{"fhir": {...Bundle...}, "recipient": "...", "sender": "...", "correlation_id": "...", ...}
//	{...Bundle...}   — a bare FHIR resource, with x-hcx-* values in HTTP headers
//
// The envelope may also carry a "jwe_headers" map (hcxkit spelling) and the
// x-hcx-* keys directly. HTTP headers fill in whatever the body leaves out.
func ParseOutboundBody(path string, body []byte, httpHeaders http.Header) (OutboundRequest, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return OutboundRequest{}, &abdm.Error{Code: "INVALID_ENVELOPE", Message: "body must be a JSON object", Err: err}
	}
	req := OutboundRequest{Path: path, Headers: map[string]any{}}

	// Lowest precedence: HTTP headers.
	for _, k := range protectedKeys {
		if v := httpHeaders.Get(k); v != "" {
			req.Headers[k] = v
		}
	}
	// Then the hcxkit-style map.
	if raw, ok := obj["jwe_headers"]; ok {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return OutboundRequest{}, &abdm.Error{Code: "INVALID_ENVELOPE", Message: "jwe_headers must be an object", Err: err}
		}
		for k, v := range m {
			req.Headers[k] = v
		}
	}
	// Then top-level x-hcx-* keys and their short aliases.
	for _, k := range protectedKeys {
		if raw, ok := obj[k]; ok {
			req.Headers[k] = rawString(raw)
		}
	}
	for alias, k := range aliases {
		if raw, ok := obj[alias]; ok {
			req.Headers[k] = rawString(raw)
		}
	}

	switch {
	case len(obj["fhir"]) > 0:
		req.FHIR = obj["fhir"]
	case len(obj["payload"]) > 0:
		req.FHIR = obj["payload"]
	case len(obj["resourceType"]) > 0:
		req.FHIR = body
	default:
		return OutboundRequest{}, &abdm.Error{Code: "INVALID_ENVELOPE", Message: `body needs a "fhir" object or must itself be a FHIR resource`}
	}
	return req, nil
}

var protectedKeys = []string{
	nhcx.HdrSender, nhcx.HdrRecipient, nhcx.HdrCorrelationID, nhcx.HdrRequestID,
	nhcx.HdrAPICallID, nhcx.HdrWorkflowID, nhcx.HdrStatus, nhcx.HdrTimestamp,
}

var aliases = map[string]string{
	"sender":         nhcx.HdrSender,
	"recipient":      nhcx.HdrRecipient,
	"correlation_id": nhcx.HdrCorrelationID,
	"request_id":     nhcx.HdrRequestID,
	"api_call_id":    nhcx.HdrAPICallID,
	"workflow_id":    nhcx.HdrWorkflowID,
	"status":         nhcx.HdrStatus,
}

func rawString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func compactJSON(raw json.RawMessage) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return raw
	}
	return buf.Bytes()
}

// -------------------------------------------------------------- inbound ----

// Inbound is one message received from NHCX, decrypted.
type Inbound struct {
	// Path is the NHCX API path it arrived on, e.g. "v1/preauth/on_submit".
	Path string
	// Kind is "fhir" (decrypted JWE), "protocol" (a plain-JSON
	// ProtocolResponse / error notice) or "json" (anything else).
	Kind string
	// Headers are the x-hcx-* protected headers (or the protocol message's
	// top-level ones).
	Headers map[string]any
	// Payload is the decrypted bundle, or the plain body for the other kinds.
	Payload json.RawMessage
	// ReceivedAt stamps the delivery envelope.
	ReceivedAt time.Time
	// RemoteAddr is who posted it (for the delivery envelope's meta).
	RemoteAddr string
	// Redelivery is set when the ledger already holds this api_call_id:
	// NHCX is retrying, and the backend should treat it idempotently.
	Redelivery bool
	// LedgerID is filled in once the message is recorded.
	LedgerID string
}

// PeekHeaders reads the protected header of a JWE body without decrypting
// it, so a refused message can still be recorded with its ids.
func PeekHeaders(body []byte) map[string]any {
	var obj struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(body, &obj) != nil || !nhcx.IsCompactJWE(obj.Payload) {
		return nil
	}
	h, _ := nhcx.ParseHeader(obj.Payload)
	return h
}

// Receive parses and decrypts what NHCX posted to path.
func (g *Gateway) Receive(path string, body []byte, remoteAddr string) (*Inbound, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, &abdm.Error{Code: "INVALID_BODY", Message: "body must be a JSON object", Err: err}
	}
	in := &Inbound{Path: nhcx.CleanPath(path), ReceivedAt: time.Now(), RemoteAddr: remoteAddr}

	if raw, ok := obj["payload"]; ok {
		var compact string
		if err := json.Unmarshal(raw, &compact); err != nil || !nhcx.IsCompactJWE(compact) {
			return nil, &abdm.Error{Code: "INVALID_JWE", Message: `"payload" must be a compact JWE string`}
		}
		headers, err := nhcx.ParseHeader(compact)
		if err != nil {
			return nil, &abdm.Error{Code: "INVALID_JWE", Message: "unreadable JWE protected header", Err: err}
		}
		if rc := nhcx.GetString(headers, nhcx.HdrRecipient); rc != "" && !nhcx.SameCode(rc, g.cfg.Participant.ParticipantID) {
			return nil, &abdm.Error{Code: "WRONG_RECIPIENT", Message: fmt.Sprintf("message is addressed to %s, this gateway is %s", nhcx.NormalizeCode(rc), g.cfg.Participant.ParticipantID)}
		}
		plain, err := nhcx.Decrypt(compact, g.priv)
		if err != nil {
			return nil, &abdm.Error{Code: "DECRYPT_FAILED", Message: "payload could not be decrypted with this participant's private key", Err: err}
		}
		if !json.Valid(plain) {
			plain, _ = json.Marshal(string(plain))
		}
		in.Kind = "fhir"
		in.Headers = normalizeHeaders(headers)
		in.Payload = plain
		in.Redelivery = g.ledger != nil && g.ledger.Seen(ledger.In, nhcx.GetString(in.Headers, nhcx.HdrAPICallID))
		return in, nil
	}

	// No JWE: a ProtocolResponse / v1/error notice carries its protocol
	// headers at the top level of a plain JSON body.
	in.Payload = body
	in.Headers = map[string]any{}
	for k, raw := range obj {
		if strings.HasPrefix(k, "x-hcx-") {
			var v any
			_ = json.Unmarshal(raw, &v)
			in.Headers[k] = v
		}
	}
	_, hasType := obj["type"]
	if len(in.Headers) > 0 || hasType {
		in.Kind = "protocol"
	} else {
		in.Kind = "json"
	}
	in.Headers = normalizeHeaders(in.Headers)
	in.Redelivery = g.ledger != nil && g.ledger.Seen(ledger.In, nhcx.GetString(in.Headers, nhcx.HdrAPICallID))
	return in, nil
}

// RecordInbound writes an inbound message and its delivery outcome to the
// ledger. res may be nil (never delivered); err is the delivery or receive
// error, if any.
func (g *Gateway) RecordInbound(in *Inbound, res *DeliveryResult, err error) {
	if g.ledger == nil || in == nil {
		return
	}
	entry := &ledger.Entry{
		Direction: ledger.In, CreatedAt: in.ReceivedAt, Path: in.Path, Format: in.Kind,
		Sender: nhcx.GetString(in.Headers, nhcx.HdrSender), Recipient: nhcx.GetString(in.Headers, nhcx.HdrRecipient),
		CorrelationID: nhcx.GetString(in.Headers, nhcx.HdrCorrelationID), APICallID: nhcx.GetString(in.Headers, nhcx.HdrAPICallID),
		RequestID: nhcx.GetString(in.Headers, nhcx.HdrRequestID), WorkflowID: nhcx.GetString(in.Headers, nhcx.HdrWorkflowID),
		HCXStatus: nhcx.GetString(in.Headers, nhcx.HdrStatus), Headers: in.Headers, FHIR: in.Payload, Redelivery: in.Redelivery,
		DurationMs: time.Since(in.ReceivedAt).Milliseconds(),
	}
	if res != nil {
		entry.Peer = &ledger.Peer{URL: res.URL, StatusCode: res.StatusCode}
		if json.Valid(res.Body) {
			entry.Peer.Response = json.RawMessage(res.Body)
		} else if len(res.Body) > 0 {
			entry.Peer.Response, _ = json.Marshal(string(res.Body))
		}
		entry.DurationMs = res.Duration.Milliseconds()
	}
	switch {
	case err == nil:
		entry.Status = ledger.StatusDelivered
	default:
		e := abdm.AsError(err)
		entry.Error = &ledger.Error{Code: e.Code, Message: e.Message}
		if strings.HasPrefix(e.Code, "CALLBACK_") {
			entry.Status = ledger.StatusDeliveryFailed
		} else {
			entry.Status = ledger.StatusRejected
		}
	}
	g.record(entry)
	in.LedgerID = entry.ID

	level := slog.LevelInfo
	if entry.Status != ledger.StatusDelivered {
		level = slog.LevelWarn
	}
	attrs := []any{"path", in.Path, "kind", in.Kind, "sender", entry.Sender, "recipient", entry.Recipient, "status", entry.Status,
		"took_ms", entry.DurationMs, "correlation_id", entry.CorrelationID, "api_call_id", entry.APICallID, "redelivery", in.Redelivery, "ledger_id", entry.ID}
	if res != nil {
		attrs = append(attrs, "callback", res.StatusCode)
	}
	if entry.Error != nil {
		attrs = append(attrs, "error", entry.Error.Code)
	}
	g.log.Log(context.Background(), level, "inbound", attrs...)
}

// RecordRefused records an inbound message the gateway could not even parse
// or decrypt, so the attempt is visible in the ledger.
func (g *Gateway) RecordRefused(path, remoteAddr string, headers map[string]any, err error) {
	if g.ledger == nil {
		return
	}
	in := &Inbound{Path: nhcx.CleanPath(path), Kind: "unknown", Headers: normalizeHeaders(headers), ReceivedAt: time.Now(), RemoteAddr: remoteAddr}
	g.RecordInbound(in, nil, err)
}

func normalizeHeaders(h map[string]any) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		if v == nil {
			continue
		}
		out[k] = v
	}
	for _, k := range []string{nhcx.HdrSender, nhcx.HdrRecipient} {
		if c := nhcx.NormalizeCode(nhcx.GetString(out, k)); c != "" {
			out[k] = c
		}
	}
	return out
}

// DeliveryResult is the integrator backend's answer to a delivery.
type DeliveryResult struct {
	URL        string
	StatusCode int
	Body       []byte
	Duration   time.Duration
}

// DeliveryURL is where an inbound message on path is posted: the route
// configured for that exact path, else callback.url (+ path).
func (g *Gateway) DeliveryURL(path string) string {
	if u, ok := g.cfg.Callback.Routes[nhcx.CleanPath(path)]; ok && u != "" {
		return u
	}
	base := strings.TrimRight(g.cfg.Callback.URL, "/")
	if !g.cfg.CallbackAppendsPath() || nhcx.CleanPath(path) == "" {
		return base
	}
	return base + "/" + nhcx.CleanPath(path)
}

// Envelope is the JSON body delivered to the callback. It mirrors the hcxkit
// inbound envelope so a backend written for the kit needs no change.
func (in *Inbound) Envelope() map[string]any {
	return map[string]any{
		"meta": map[string]any{
			"type":        "in",
			"payloadType": in.Kind,
			"path":        in.Path,
			"ip":          in.RemoteAddr,
			"time":        in.ReceivedAt.Format(time.RFC3339),
			"redelivery":  in.Redelivery,
		},
		"jwe_headers": in.Headers,
		"fhir":        in.Payload,
	}
}

// Deliver posts the decrypted message to the integrator and waits for the
// answer. A non-2xx answer is returned as an error so the caller can refuse
// NHCX's delivery and let the exchange retry.
func (g *Gateway) Deliver(ctx context.Context, in *Inbound) (*DeliveryResult, error) {
	target := g.DeliveryURL(in.Path)
	body, err := json.Marshal(in.Envelope())
	if err != nil {
		return nil, &abdm.Error{Code: "MARSHAL_ERROR", Message: "encode delivery envelope", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, &abdm.Error{Code: "CALLBACK_REQUEST", Message: "build callback request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Nhcx-Path", in.Path)
	req.Header.Set("X-Nhcx-Payload-Kind", in.Kind)
	req.Header.Set("X-Nhcx-Correlation-Id", nhcx.GetString(in.Headers, nhcx.HdrCorrelationID))
	req.Header.Set("X-Nhcx-Api-Call-Id", nhcx.GetString(in.Headers, nhcx.HdrAPICallID))
	if in.Redelivery {
		req.Header.Set("X-Nhcx-Redelivery", "true")
	}
	if g.cfg.Callback.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.Callback.APIKey)
	}

	start := time.Now()
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, &abdm.Error{Code: "CALLBACK_UNREACHABLE", Message: "callback " + target + " unreachable", Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	res := &DeliveryResult{URL: target, StatusCode: resp.StatusCode, Body: respBody, Duration: time.Since(start)}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return res, &abdm.Error{
			Code: fmt.Sprintf("CALLBACK_HTTP_%d", resp.StatusCode), Message: "callback rejected the message",
			Retryable: resp.StatusCode >= 500 || resp.StatusCode == 429, Status: resp.StatusCode, Body: string(respBody),
		}
	}
	return res, nil
}

// Acceptance builds the HTTP 202 body NHCX requires from a recipient.
func (in *Inbound) Acceptance() map[string]any {
	return map[string]any{
		"timestamp":      nhcx.AckTimestamp(time.Now()),
		"api_call_id":    nhcx.EnsureID(nhcx.GetString(in.Headers, nhcx.HdrAPICallID)),
		"correlation_id": nhcx.EnsureID(nhcx.GetString(in.Headers, nhcx.HdrCorrelationID)),
		"result": map[string]any{
			"sender_code":     nhcx.GetString(in.Headers, nhcx.HdrSender),
			"recipient_code":  nhcx.GetString(in.Headers, nhcx.HdrRecipient),
			"entity_type":     nhcx.EntityType(in.Path),
			"protocol_status": "request.queued",
		},
		"error": map[string]any{"code": "", "message": ""},
	}
}

// Decrypt opens a compact JWE with this participant's key (CLI helper).
func (g *Gateway) Decrypt(compact string) (map[string]any, []byte, error) {
	headers, err := nhcx.ParseHeader(compact)
	if err != nil {
		return nil, nil, err
	}
	plain, err := nhcx.Decrypt(compact, g.priv)
	if err != nil {
		return headers, nil, err
	}
	return headers, plain, nil
}

// ErrNotDelivered is wrapped around callback failures by the server.
var ErrNotDelivered = errors.New("not delivered")

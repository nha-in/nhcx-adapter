package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"nhcx-adapter/internal/abdm"
	"nhcx-adapter/internal/ledger"
)

// hcxkit publishes an /internal console API alongside the exchange routes,
// and backends written against the kit call a little of it before they can
// send. Two endpoints are enough for that:
//
//   - GET  /internal/config/get          — "what participant am I?", which a
//     sender needs to fill in x-hcx-sender_code when it has no code of its own
//     configured;
//   - POST /internal/participants/search — the registry record for a code, to
//     put a name and registry id on the Organization in a bundle.
//
// Neither is part of the exchange, and this is not an attempt to reimplement
// the kit's console: the txn browser, the mapping editor, the policy and
// adjudicator hooks are all still kit-only. These two exist because without
// them a kit client cannot get as far as its first message.

// kitConfig answers the shape hcxkit's /internal/config/get returns, reduced
// to what a client actually reads. Nothing secret is included — no client
// secret, no private key — because this endpoint sits behind the same door as
// the console and a config dump is not what it is for.
func (s *Server) kitConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.gw.Config()
	profiles := make([]map[string]any, 0, s.gw.Profiles().Len())
	for _, prof := range s.gw.Profiles().All() {
		profiles = append(profiles, map[string]any{
			"participantId": prof.Code(),
			"name":          prof.Participant.Name,
			"callbackUrl":   prof.Callback.URL,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"participant": map[string]any{
			"participantId": cfg.Participant.ParticipantID,
			"name":          cfg.Participant.Name,
			"callbackUrl":   cfg.Callback.URL,
		},
		"participants": profiles[1:],
		"CMID":         cfg.CMID,
		"env":          cfg.Env,
		"urls": map[string]any{
			"nhcx":        cfg.URLs.NHCX,
			"participant": cfg.URLs.Participant,
			"sessions":    cfg.URLs.Sessions,
		},
	})
}

// kitParticipantSearch answers hcxkit's /internal/participants/search with the
// registry record for one code. Callers treat a failure as "no record" rather
// than an error, so an unknown code is an empty answer, not a 404.
func (s *Server) kitParticipantSearch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ParticipantCode string `json:"participant_code"`
		ParticipantID   string `json:"participantid"`
		Code            string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		s.fail(w, r, &abdm.Error{Code: "INVALID_BODY", Status: http.StatusBadRequest,
			Message: "body must be a JSON object with participant_code"})
		return
	}
	code := body.ParticipantCode
	for _, alt := range []string{body.ParticipantID, body.Code} {
		if code == "" {
			code = alt
		}
	}
	if code == "" {
		writeJSON(w, http.StatusOK, map[string]any{"participants": []any{}})
		return
	}

	p, err := s.gw.ABDMFor(code).FetchParticipant(r.Context(), code)
	if err != nil || p == nil {
		writeJSON(w, http.StatusOK, map[string]any{"participants": []any{}})
		return
	}
	// The registry's own record is passed through, with the field names the
	// kit's readers look for laid over it.
	record := map[string]any{}
	for k, v := range p.Raw {
		record[k] = v
	}
	record["participant_code"] = p.Code
	record["participant_name"] = p.Name
	record["endpoint_url"] = p.EndpointURL
	if p.Status != "" {
		record["status"] = p.Status
	}
	if len(p.Roles) > 0 {
		record["roles"] = p.Roles
	}
	writeJSON(w, http.StatusOK, map[string]any{"participants": []any{record}})
}

// ---------------------------------------------------------------- txns ----
//
// nanoemr does not wait for its callback to be poked: it polls the adapter
// for the other side's answer, walking the thread its own send opened. That
// is three more kit endpoints, and the ledger already holds everything they
// report — a transaction id here is a ledger id, which is what /out and
// /fhir/out answer as txn_id.

// txnID reads the {"txnId": "..."} body these endpoints take.
func (s *Server) txnID(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		TxnID string `json:"txnId"`
		Alt   string `json:"txn_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		s.fail(w, r, &abdm.Error{Code: "INVALID_BODY", Status: http.StatusBadRequest,
			Message: `body must be a JSON object with "txnId"`})
		return "", false
	}
	id := body.TxnID
	if id == "" {
		id = body.Alt
	}
	if id == "" {
		s.fail(w, r, &abdm.Error{Code: "NO_TXN_ID", Status: http.StatusBadRequest,
			Message: `"txnId" is required`})
		return "", false
	}
	return id, true
}

// entryOr404 finds a ledger entry. A missing one is a 404 on purpose: the
// kit's clients read that as "this transaction is gone, stop polling for a
// reply that can never arrive" rather than as a transient fault.
func (s *Server) entryOr404(w http.ResponseWriter, r *http.Request, id string) (*ledger.Entry, bool) {
	store := s.gw.Ledger()
	if store == nil {
		s.fail(w, r, &abdm.Error{Code: "LEDGER_DISABLED", Status: http.StatusNotFound,
			Message: "the ledger is turned off, so no transaction can be looked up"})
		return nil, false
	}
	entry, err := store.Get(id)
	if err != nil || entry == nil {
		s.fail(w, r, &abdm.Error{Code: "TXN_NOT_FOUND", Status: http.StatusNotFound,
			Message: "no transaction " + id})
		return nil, false
	}
	return entry, true
}

// kitTxnRelated answers every message on the same correlation as txnId, in
// both directions — the thread a client walks to find the reply to its send.
func (s *Server) kitTxnRelated(w http.ResponseWriter, r *http.Request) {
	id, ok := s.txnID(w, r)
	if !ok {
		return
	}
	entry, ok := s.entryOr404(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, kitRows(s.gw.Ledger().List(
		ledger.Query{CorrelationID: entry.CorrelationID, Limit: 500})))
}

// kitTxnList answers the recent ledger, newest first — what a client scans
// when it has no transaction id to start from, looking for a protocol error
// that closed a thread it is still waiting on.
func (s *Server) kitTxnList(w http.ResponseWriter, r *http.Request) {
	store := s.gw.Ledger()
	if store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, kitRows(store.List(ledger.Query{Limit: limit})))
}

// kitRows maps ledger summaries into the row shape the kit's clients read.
func kitRows(summaries []ledger.Summary) []map[string]any {
	rows := make([]map[string]any, 0, len(summaries))
	for _, m := range summaries {
		rows = append(rows, map[string]any{
			"id":             m.ID,
			"direction":      m.Direction,
			"status":         m.Status,
			"sender":         m.Sender,
			"recipient":      m.Recipient,
			"correlation_id": m.CorrelationID,
			"api_call_id":    m.APICallID,
			"type":           m.Entity,
			"flow":           m.Action,
			"created_at":     m.CreatedAt,
		})
	}
	return rows
}

// kitTxnFHIR answers one transaction's envelope: the protected headers and
// the bundle, in the same shape a delivery carries.
func (s *Server) kitTxnFHIR(w http.ResponseWriter, r *http.Request) {
	id, ok := s.txnID(w, r)
	if !ok {
		return
	}
	entry, ok := s.entryOr404(w, r, id)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"meta": map[string]any{
			"type":        map[bool]string{true: "in", false: "out"}[entry.Direction == ledger.In],
			"payloadType": entry.Format,
			"path":        entry.Path,
			"time":        entry.CreatedAt,
		},
		"jwe_headers": entry.Headers,
		"fhir":        entry.FHIR,
	})
}

// kitTxnDispatch reports what became of a send. On hcxkit this asks a queue
// worker to try again; this adapter dispatches synchronously inside the /out
// call, so by the time a transaction has an id its fate is already decided
// and there is nothing to retry. The answer says so in the kit's own
// vocabulary, which is what its clients branch on.
func (s *Server) kitTxnDispatch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.txnID(w, r)
	if !ok {
		return
	}
	entry, ok := s.entryOr404(w, r, id)
	if !ok {
		return
	}
	out := map[string]any{"txnId": entry.ID, "status": entry.Status}
	switch entry.Status {
	case ledger.StatusFailed, ledger.StatusRejected:
		// The kit's clients treat these three as terminal and stop polling.
		out["status"] = "dispatch_failed"
	case ledger.StatusAccepted, ledger.StatusDelivered:
		out["status"] = "dispatched"
	}
	if entry.Error != nil {
		out["errorCode"] = entry.Error.Code
		out["errorMessage"] = entry.Error.Message
	}
	writeJSON(w, http.StatusOK, out)
}

// ------------------------------------------------- participant service ----
//
// The rest of the kit's /internal surface that these apps use is pass-through:
// a POST to the ABDM participant service carrying the session token, with the
// registry's answer handed back untouched. The adapter models none of it —
// policies and registry records are ABDM's, not ours — so proxying is not a
// shortcut, it is the whole job.

// proxyRegistry forwards the request body to a participant-service path and
// answers with whatever came back, status included. Upstream failures are
// meaningful to the caller — the registry reports "nothing linked to this
// identifier" as an error (NHCX-1016), which a caller reads as an empty
// result — so the status is passed through rather than translated.
func (s *Server) proxyRegistry(w http.ResponseWriter, r *http.Request, path string, body any) {
	status, raw, err := s.gw.ABDM().PostRegistry(r.Context(), path, body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !json.Valid(raw) {
		// Some registry failures come back as plain text.
		raw, _ = json.Marshal(map[string]any{"error": string(raw)})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// rawBody reads the caller's JSON object to forward verbatim.
func (s *Server) rawBody(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var body map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, &abdm.Error{Code: "INVALID_BODY", Status: http.StatusBadRequest,
			Message: "body must be a JSON object"})
		return nil, false
	}
	return body, true
}

// kitPolicySearch answers hcxkit's /internal/policies/search: the health
// policies the ABDM registry has linked to a person, by ABHA number or
// mobile.
func (s *Server) kitPolicySearch(w http.ResponseWriter, r *http.Request) {
	body, ok := s.rawBody(w, r)
	if !ok {
		return
	}
	str := func(k string) string { v, _ := body[k].(string); return v }
	kind, value := str("identifiertype"), str("identifiervalue")
	if kind == "" {
		// The spellings older callers use.
		switch {
		case str("mobile") != "":
			kind, value = "MobileNo", str("mobile")
		case str("abhaNo") != "":
			kind, value = "AbhaNumber", str("abhaNo")
		}
	}
	if value == "" {
		s.fail(w, r, &abdm.Error{Code: "NO_IDENTIFIER", Status: http.StatusBadRequest,
			Message: "identifiervalue (or mobile / abhaNo) is required"})
		return
	}
	s.proxyRegistry(w, r, "participant/get/policies",
		map[string]string{"identifiertype": kind, "identifiervalue": value})
}

// kitAbhaLink and kitAbhaDelink attach and detach a policy from an ABHA
// number. The body is the caller's, forwarded as sent: what the registry
// requires here is ABDM's business and changes without us.
func (s *Server) kitAbhaLink(w http.ResponseWriter, r *http.Request) {
	if body, ok := s.rawBody(w, r); ok {
		s.proxyRegistry(w, r, "participant/link/abha/policy", body)
	}
}

func (s *Server) kitAbhaDelink(w http.ResponseWriter, r *http.Request) {
	if body, ok := s.rawBody(w, r); ok {
		s.proxyRegistry(w, r, "participant/delink/abha/policy", body)
	}
}

// kitParticipantsList answers the registry's participant roster.
func (s *Server) kitParticipantsList(w http.ResponseWriter, r *http.Request) {
	body, ok := s.rawBody(w, r)
	if !ok {
		return
	}
	s.proxyRegistry(w, r, "fetch/participants/list", body)
}

// kitParticipantCerts answers a counterparty's encryption certificate, from
// the adapter's own cache when it is fresh — the certificate is the one thing
// here the adapter does model, because it needs it to encrypt.
func (s *Server) kitParticipantCerts(w http.ResponseWriter, r *http.Request) {
	body, ok := s.rawBody(w, r)
	if !ok {
		return
	}
	code, _ := body["participantid"].(string)
	if code == "" {
		code, _ = body["participant_code"].(string)
	}
	if code == "" {
		s.fail(w, r, &abdm.Error{Code: "NO_RECIPIENT", Status: http.StatusBadRequest,
			Message: "participantid is required"})
		return
	}
	_, pem, err := s.gw.ABDMFor(code).Certificate(r.Context(), code)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"participant_code": code, "encryption_cert": pem,
	})
}

// kitSavedParticipants is hcxkit's own list of participants an operator
// pinned in its console — local state this adapter keeps none of. The
// configured profiles are the honest answer: those are the participants it
// actually knows. Callers treat the list as a convenience and fall back to
// asking the registry, so an unfamiliar shape here costs nothing.
func (s *Server) kitSavedParticipants(w http.ResponseWriter, r *http.Request) {
	rows := []map[string]any{}
	for _, prof := range s.gw.Profiles().All() {
		rows = append(rows, map[string]any{
			"participant_code": prof.Code(),
			"participant_name": prof.Participant.Name,
			"local":            true,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"participants": rows})
}

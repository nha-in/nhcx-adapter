package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const claimBundle = `{"resourceType":"Bundle","type":"collection","entry":[
 {"resource":{"resourceType":"Composition","id":"c1"}},
 {"resource":{"resourceType":"Claim","id":"cl-1","identifier":[{"value":"CLM-42"}]}},
 {"resource":{"resourceType":"Patient","id":"p1"}}]}`

func TestRecordListThread(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, RetentionDays: 30, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	out := &Entry{Direction: Out, CreatedAt: base, Path: "/v1/claim/submit/", Sender: "1@hcx", Recipient: "2@hcx",
		CorrelationID: "corr-1", APICallID: "api-1", HCXStatus: "request.initiated", Status: StatusAccepted,
		Peer: &Peer{URL: "https://x", StatusCode: 202, Response: json.RawMessage(`{"ok":true}`)}, FHIR: json.RawMessage(claimBundle)}
	if err := s.Record(out); err != nil {
		t.Fatal(err)
	}
	if out.ID == "" || out.Entity != "claim" || out.Action != "submit" || out.Kind != "request" || out.Path != "v1/claim/submit" {
		t.Errorf("derived fields: %+v", out)
	}
	if sm := out.Summary; sm == nil || sm.Focus != "Claim/cl-1" || sm.Identifier != "CLM-42" || sm.Patient != "Patient/p1" || sm.Entries != 3 || sm.ResourceTypes["Claim"] != 1 {
		t.Errorf("fhir summary: %+v", out.Summary)
	}
	if th := s.Thread("corr-1", "1@hcx"); th == nil || th.State != ThreadAwaitingResponse || th.Role != "initiator" || th.Counterparty != "2@hcx" {
		t.Errorf("thread after request: %+v", th)
	}

	in := &Entry{Direction: In, CreatedAt: base.Add(time.Minute), Path: "v1/claim/on_submit", Sender: "2@hcx", Recipient: "1@hcx",
		CorrelationID: "corr-1", APICallID: "api-2", HCXStatus: "response.complete", Status: StatusDelivered, Format: "fhir",
		FHIR: json.RawMessage(`{"resourceType":"Bundle","type":"collection","entry":[{"resource":{"resourceType":"ClaimResponse","id":"r1","outcome":"complete"}}]}`)}
	if err := s.Record(in); err != nil {
		t.Fatal(err)
	}
	if in.Summary == nil || in.Summary.Outcome != "complete" {
		t.Errorf("response summary: %+v", in.Summary)
	}
	th := s.Thread("corr-1", "1@hcx")
	if th.State != ThreadCompleted || len(th.Messages) != 2 || th.Updated != in.CreatedAt {
		t.Errorf("thread after response: %+v", th)
	}
	if s.Thread("nope", "") != nil {
		t.Error("unknown thread must be nil")
	}

	// Filters.
	if got := s.List(Query{Direction: In}); len(got) != 1 || got[0].ID != in.ID {
		t.Errorf("direction filter: %v", got)
	}
	if got := s.List(Query{Participant: "2"}); len(got) != 2 {
		t.Errorf("participant filter (either side, either spelling): %d", len(got))
	}
	if got := s.List(Query{Since: base.Add(30 * time.Second)}); len(got) != 1 {
		t.Errorf("since filter: %d", len(got))
	}
	if got := s.List(Query{Before: in.ID}); len(got) != 1 || got[0].ID != out.ID {
		t.Errorf("before paging: %v", got)
	}
	if got := s.List(Query{}); got[0].ID != in.ID {
		t.Error("newest first")
	}
	if !s.Seen(In, "api-2") || s.Seen(Out, "api-2") || s.Seen(In, "") {
		t.Error("Seen")
	}

	// Correlation lookup for a response we are about to send.
	req := &Entry{Direction: In, CreatedAt: base.Add(2 * time.Minute), Path: "v1/preauth/submit", Sender: "3@hcx", Recipient: "1@hcx",
		CorrelationID: "corr-2", APICallID: "api-3", WorkflowID: "wf", Status: StatusDelivered}
	_ = s.Record(req)
	if got := s.LastInboundRequest("preauth", "3", ""); got == nil || got.CorrelationID != "corr-2" {
		t.Errorf("LastInboundRequest: %+v", got)
	}
	if got := s.LastInboundRequest("preauth", "3", "other-wf"); got != nil {
		t.Error("workflow filter must apply")
	}
	if th := s.Thread("corr-2", ""); th.State != ThreadAwaitingOurResponse || th.Role != "responder" {
		t.Errorf("responder thread: %+v", th)
	}

	// Full read, stats, reload from disk.
	e, err := s.Get(out.ID)
	if err != nil || string(e.FHIR) == "" || e.Peer.StatusCode != 202 || e.Headers != nil {
		t.Errorf("Get: %v %+v", err, e)
	}
	if _, err := s.Get("../etc/passwd"); err != ErrNotFound {
		t.Error("bad ids are not found")
	}
	st := s.Stats()
	if st.Total != 3 || st.Threads != 2 || st.ByDirection[In] != 2 || st.ByEntity["claim"] != 2 {
		t.Errorf("stats: %+v", st)
	}
	again, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := again.List(Query{}); len(got) != 3 || got[0].ID != req.ID || !again.Seen(In, "api-2") {
		t.Errorf("reload: %v", got)
	}

	// Sweep drops old day folders.
	s2, _ := Open(Options{Dir: dir, RetentionDays: 7, StoreBodies: true})
	if n := s2.Sweep(base.Add(3 * 24 * time.Hour)); n != 0 {
		t.Errorf("nothing older than 7 days yet, removed %d", n)
	}
	if n := s2.Sweep(base.Add(10 * 24 * time.Hour)); n != 3 || s2.Stats().Total != 0 || s2.Seen(In, "api-2") {
		t.Errorf("sweep: removed %d, stats %+v", n, s2.Stats())
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-08-26")); !os.IsNotExist(err) {
		t.Error("day folder should be gone")
	}
}

func TestNoBodies(t *testing.T) {
	s, err := Open(Options{Dir: t.TempDir(), StoreBodies: false})
	if err != nil {
		t.Fatal(err)
	}
	e := &Entry{Direction: Out, Path: "v1/claim/submit", Status: StatusAccepted, FHIR: json.RawMessage(claimBundle),
		Peer: &Peer{StatusCode: 202, Response: json.RawMessage(`{"x":1}`)}}
	if err := s.Record(e); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(e.ID)
	if got.FHIR != nil || got.Peer.Response != nil || got.Summary == nil {
		t.Errorf("bodies must be dropped but the summary kept: %+v", got)
	}
}

func TestDeriveState(t *testing.T) {
	cases := []struct {
		msgs []Summary
		want string
	}{
		{[]Summary{{Direction: Out, Kind: "request", Status: StatusFailed}}, ThreadError},
		{[]Summary{{Direction: Out, Kind: "request", Status: StatusAccepted}, {Direction: In, Kind: "response", Status: StatusDelivered, HCXStatus: "response.partial"}}, ThreadPartial},
		{[]Summary{{Direction: Out, Kind: "request", Status: StatusAccepted}, {Direction: In, Format: "protocol", Status: StatusDelivered, HCXStatus: "response.error"}}, ThreadError},
		{[]Summary{{Direction: In, Kind: "request", Status: StatusDeliveryFailed}}, ThreadAwaitingOurResponse},
	}
	for i, c := range cases {
		if got := deriveState(c.msgs); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

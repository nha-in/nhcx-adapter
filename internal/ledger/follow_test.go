package ledger

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// The point of Follow is that the writer is somebody else — the server
// process — so the test writes through a second Store opened on the same
// directory, as another process would.
func TestFollowSeesAnotherWriter(t *testing.T) {
	dir := t.TempDir()
	reader, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Already on record when following starts: it must not be replayed.
	old := &Entry{Direction: Out, CreatedAt: now, Path: "v1/claim/submit", Recipient: "2@hcx", Status: StatusAccepted}
	if err := writer.Record(old); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seen := make(chan Summary, 8)
	started := make(chan struct{})
	go func() {
		close(started)
		_ = reader.Follow(ctx, FollowOptions{After: old.ID, Query: Query{Direction: Out}, Interval: 10 * time.Millisecond},
			func(sm Summary) { seen <- sm })
	}()
	<-started
	time.Sleep(50 * time.Millisecond) // let the first scan find the end of the file

	// Two more messages, one of which the filter excludes.
	for _, e := range []*Entry{
		{Direction: In, CreatedAt: now.Add(time.Second), Path: "v1/claim/on_submit", Sender: "2@hcx", Status: StatusDelivered},
		{Direction: Out, CreatedAt: now.Add(2 * time.Second), Path: "v1/preauth/submit", Recipient: "2@hcx",
			CorrelationID: "corr-9", Status: StatusRejected, FHIR: json.RawMessage(`{"resourceType":"Bundle"}`)},
	} {
		if err := writer.Record(e); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case sm := <-seen:
		if sm.Path != "v1/preauth/submit" || sm.CorrelationID != "corr-9" || sm.Status != StatusRejected {
			t.Fatalf("delivered the wrong entry: %+v", sm)
		}
	case <-ctx.Done():
		t.Fatal("nothing was delivered within the timeout")
	}
	select {
	case sm := <-seen:
		t.Fatalf("the inbound message should have been filtered out, and the old one not replayed: %+v", sm)
	case <-time.After(80 * time.Millisecond):
	}
}

// A ledger cleared while it is being followed truncates the file underneath
// the reader; the next message must still arrive.
func TestFollowSurvivesClear(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(&Entry{Direction: Out, Path: "v1/claim/submit", Recipient: "2@hcx", Status: StatusAccepted}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seen := make(chan Summary, 4)
	go func() {
		_ = store.Follow(ctx, FollowOptions{Interval: 10 * time.Millisecond}, func(sm Summary) { seen <- sm })
	}()
	time.Sleep(50 * time.Millisecond)

	if _, err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the follower notices the day folder went
	if err := store.Record(&Entry{Direction: In, Path: "v1/claim/on_submit", Sender: "2@hcx", Status: StatusDelivered}); err != nil {
		t.Fatal(err)
	}
	select {
	case sm := <-seen:
		if sm.Path != "v1/claim/on_submit" {
			t.Fatalf("after a clear, got %+v", sm)
		}
	case <-ctx.Done():
		t.Fatal("the message recorded after a clear never arrived")
	}
}

func TestSubscribeDeliversAndStops(t *testing.T) {
	store, err := Open(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ch, cancel := store.Subscribe()
	if err := store.Record(&Entry{Direction: Out, Path: "v1/claim/submit", Recipient: "2@hcx", Status: StatusAccepted}); err != nil {
		t.Fatal(err)
	}
	select {
	case sm := <-ch:
		if sm.Path != "v1/claim/submit" {
			t.Fatalf("subscriber got %+v", sm)
		}
	case <-time.After(time.Second):
		t.Fatal("the subscriber was not told about a recorded message")
	}

	cancel()
	cancel() // must be safe twice
	if _, open := <-ch; open {
		t.Error("cancelling a subscription should close its channel")
	}
	// A recorded message must not panic on a closed subscriber.
	if err := store.Record(&Entry{Direction: In, Path: "v1/claim/on_submit", Sender: "2@hcx", Status: StatusDelivered}); err != nil {
		t.Fatal(err)
	}
}

package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Ids are eight characters: the UTC date, then a counter that restarts daily.
func TestIDShapeAndOrdering(t *testing.T) {
	s, err := Open(Options{Dir: t.TempDir(), StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)

	first := s.nextID(day)
	if len(first) != 8 {
		t.Fatalf("id %q is %d characters, want 8", first, len(first))
	}
	if want := dayCode(day) + "0001"; first != want {
		t.Errorf("first id of the day = %q, want %q", first, want)
	}

	// The counter climbs, and the ids sort in the order they were issued —
	// which is what "everything after X" queries rely on.
	prev := first
	for i := 0; i < 40; i++ {
		next := s.nextID(day)
		if next <= prev {
			t.Fatalf("id %q does not sort after %q", next, prev)
		}
		prev = next
	}

	// A new day restarts the counter and still sorts after the old one.
	tomorrow := s.nextID(day.AddDate(0, 0, 1))
	if tomorrow <= prev {
		t.Errorf("the next day's id %q sorts before today's %q", tomorrow, prev)
	}
	if got := tomorrow[4:]; got != "0001" {
		t.Errorf("counter should restart each day, got %q", got)
	}

	// The date is recoverable, which is how Get finds the file.
	if d, ok := idDay(first); !ok || d != "2026-08-31" {
		t.Errorf("idDay(%q) = %q %v, want 2026-08-31", first, d, ok)
	}
}

// Ids written by an older build are a different length and must still resolve
// to their day folder, or an existing ledger becomes unreadable.
func TestIDDayReadsBothSchemes(t *testing.T) {
	for _, tc := range []struct {
		id, day string
		ok      bool
	}{
		{"7UMV0001", "2026-08-31", true},
		{"20260826T101512.483920Z-3fa1c2d9", "2026-08-26", true},
		{"../etc/passwd", "", false},
		{"7UMV000", "", false},  // too short for either scheme
		{"7umv0001", "", false}, // outside the alphabet
		{"7Z000001", "", false}, // month 00 is not a date
	} {
		day, ok := idDay(tc.id)
		if ok != tc.ok || day != tc.day {
			t.Errorf("idDay(%q) = %q %v, want %q %v", tc.id, day, ok, tc.day, tc.ok)
		}
	}
}

// A restart must not hand out an id that is already a file on disk.
func TestCounterResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)

	s, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for i := 0; i < 3; i++ {
		e := &Entry{Direction: Out, Path: "v1/claim/submit", Status: StatusAccepted,
			CreatedAt: at, FHIR: json.RawMessage(`{"resourceType":"Bundle"}`)}
		if err := s.Record(e); err != nil {
			t.Fatal(err)
		}
		last = e.ID
	}

	reopened, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &Entry{Direction: Out, Path: "v1/claim/submit", Status: StatusAccepted, CreatedAt: at}
	if err := reopened.Record(e); err != nil {
		t.Fatal(err)
	}
	if e.ID <= last {
		t.Errorf("after a restart the next id was %q, which does not follow %q", e.ID, last)
	}
}

// Clear empties the ledger and leaves the store usable — the counter starts
// the day again, because it is derived from what is on record.
func TestClear(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, StoreBodies: true})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		e := &Entry{Direction: Out, Path: "v1/claim/submit", Status: StatusAccepted, CreatedAt: at,
			CorrelationID: "corr-1", FHIR: json.RawMessage(`{"resourceType":"Bundle"}`)}
		if err := s.Record(e); err != nil {
			t.Fatal(err)
		}
	}
	// Something that is not a day folder must survive: clearing the ledger is
	// not licence to empty whatever directory it was pointed at.
	if err := os.MkdirAll(filepath.Join(dir, "notes"), 0o750); err != nil {
		t.Fatal(err)
	}

	removed, err := s.Clear()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Errorf("cleared %d, want 3", removed)
	}
	if got := s.Stats().Total; got != 0 {
		t.Errorf("stats still report %d messages", got)
	}
	if len(s.List(Query{Limit: 50})) != 0 {
		t.Error("List still returns messages")
	}
	if th := s.Thread("corr-1", ""); th != nil {
		t.Error("the thread index was not emptied")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes")); err != nil {
		t.Errorf("a non-day folder was deleted: %v", err)
	}

	// Still usable, and the counter has restarted.
	e := &Entry{Direction: Out, Path: "v1/claim/submit", Status: StatusAccepted, CreatedAt: at}
	if err := s.Record(e); err != nil {
		t.Fatal(err)
	}
	if want := dayCode(at) + "0001"; e.ID != want {
		t.Errorf("first id after clear = %q, want %q", e.ID, want)
	}

	// Clearing an empty ledger is not an error.
	if n, err := s.Clear(); err != nil || n != 1 {
		t.Errorf("second Clear() = %d, %v", n, err)
	}
}

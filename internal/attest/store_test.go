// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"reflect"
	"testing"

	"github.com/go-git/go-git/v5"
)

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := git.PlainInit(dir, false); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGitRefStoreRoundTrip(t *testing.T) {
	store := GitRefStore{Path: newRepo(t)}
	subject := "9672f0b2f901fe632412c8f21026a7467fba585b"

	first := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`)
	superseding := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e1t9","signatures":[]}`)

	ref, err := store.Put(subject, first)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ref == "" {
		t.Error("Put returned an empty ref")
	}
	// Idempotent for identical bytes.
	if _, err := store.Put(subject, first); err != nil {
		t.Fatalf("Put (again): %v", err)
	}
	// Supersession publishes alongside, never mutates (§7.3.5).
	if _, err := store.Put(subject, superseding); err != nil {
		t.Fatalf("Put (superseding): %v", err)
	}

	got, err := store.List(subject)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d envelopes, want 2 (original + superseding)", len(got))
	}
	found := map[string]bool{}
	for _, envelope := range got {
		found[string(envelope)] = true
	}
	if !found[string(first)] || !found[string(superseding)] {
		t.Errorf("List missing envelopes: %v", found)
	}

	// Tag-name subjects work too (a promotion attests a tag).
	if _, err := store.Put("v0.1.1-t0.1", first); err != nil {
		t.Fatalf("Put(tag subject): %v", err)
	}
	tagged, err := store.List("v0.1.1-t0.1")
	if err != nil || len(tagged) != 1 {
		t.Fatalf("List(tag subject) = %d envelopes, err %v", len(tagged), err)
	}

	// Other subjects see nothing.
	other, err := store.List("0000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Errorf("List(other) = %v, want empty", other)
	}
}

// All walks every refs/attestations/* envelope and deduplicates by content: a
// release attestation filed under both its commit and its tag (StoreForSubjects)
// is one chain member, not two. The accepted-predecessor reader (#76 M6 Phase C)
// relies on this to discover releases without knowing subjects up front.
func TestGitRefStoreAll(t *testing.T) {
	store := GitRefStore{Path: newRepo(t)}
	commit := "9672f0b2f901fe632412c8f21026a7467fba585b"
	tag := "v0.1.0"
	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`)
	otherSubject := "0000000000000000000000000000000000000000"
	other := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e1t9","signatures":[]}`)

	// Same bytes under two subjects (the StoreForSubjects pattern) + a distinct
	// envelope under a third subject.
	if _, err := store.Put(commit, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(tag, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(otherSubject, other); err != nil {
		t.Fatal(err)
	}

	all, err := store.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("All returned %d envelopes, want 2 (the shared one deduped + the distinct one)", len(all))
	}
	found := map[string]bool{}
	for _, e := range all {
		found[string(e)] = true
	}
	if !found[string(envelope)] || !found[string(other)] {
		t.Errorf("All missing envelopes: %v", found)
	}
}

func TestGitRefStoreRejectsBadSubjects(t *testing.T) {
	store := GitRefStore{Path: newRepo(t)}
	for _, subject := range []string{"", "../escape", "/lead", "trail/", "sp ace", "col:on", "star*"} {
		if _, err := store.Put(subject, []byte("x")); err == nil {
			t.Errorf("Put accepted subject %q", subject)
		}
		if _, err := store.List(subject); err == nil {
			t.Errorf("List accepted subject %q", subject)
		}
	}
}

var _ Store = GitRefStore{}

func TestStoreNeverVerifies(t *testing.T) {
	// The storage layer is a dumb transport (§8.2): garbage bytes store and
	// retrieve unchanged; verification is Verify's job alone.
	store := GitRefStore{Path: newRepo(t)}
	garbage := []byte("not an envelope at all")
	if _, err := store.Put("deadbeef", garbage); err != nil {
		t.Fatal(err)
	}
	got, err := store.List("deadbeef")
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], garbage) {
		t.Errorf("round-trip altered bytes: %v %v", got, err)
	}
}

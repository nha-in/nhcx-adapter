// Package participant resolves which local identity a message belongs to.
//
// The gateway historically held exactly one — the top-level "participant"
// config section. It can now also host additional profiles from the
// "participants" array, each with its own registry code and callback, so one
// process can front a provider and a payer at once. The default profile is
// the fallback for anything that cannot be matched to a code, which is what
// keeps single-participant installs behaving exactly as before.
//
// A Set is built once at startup and never mutated, so it is safe to share
// across goroutines without a lock.
package participant

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"nhcx-gateway/internal/config"
	"nhcx-gateway/internal/keys"
	"nhcx-gateway/internal/nhcx"
)

// Profile is one resolved identity: its config entry, its parsed key and the
// callback its inbound traffic is delivered to.
type Profile struct {
	// Participant is the config entry, with credentials and key already
	// inherited from the default profile where the entry set none.
	Participant config.Participant
	// Callback is the merged callback for this profile.
	Callback config.Callback
	// Key is the RSA key this profile decrypts with. Profiles that share the
	// default's certificate share this pointer.
	Key *rsa.PrivateKey
	// Default marks the top-level "participant" section.
	Default bool
}

// Code returns the profile's normalized registry code.
func (p *Profile) Code() string { return p.Participant.ParticipantID }

// Label names the profile for logs.
func (p *Profile) Label() string { return p.Participant.Label() }

// PublicKey is the profile's own encryption key, or nil when it has none.
func (p *Profile) PublicKey() *rsa.PublicKey {
	if p.Key == nil {
		return nil
	}
	return &p.Key.PublicKey
}

// Set is every profile a gateway holds, the default first. Every method is
// safe on a nil Set, which reads as "no identities configured".
type Set struct {
	profiles []*Profile
	byCode   map[string]*Profile
}

// Build resolves every profile in cfg. It fails when a profile's key cannot
// be parsed — a gateway that cannot decrypt for an identity it advertises
// would only discover that on the first live message.
func Build(cfg *config.Config) (*Set, error) {
	all := cfg.AllParticipants()
	set := &Set{
		profiles: make([]*Profile, 0, len(all)),
		byCode:   make(map[string]*Profile, len(all)),
	}
	// Keys are parsed once per distinct material: hosted profiles usually
	// inherit the default's, and RSA parsing is not free.
	parsed := map[string]*rsa.PrivateKey{}

	for i, entry := range all {
		where := "participant"
		if i > 0 {
			where = fmt.Sprintf("participants[%d]", i-1)
		}
		key, ok := parsed[entry.PrivateKey]
		if !ok {
			var err error
			if key, err = keys.ParsePrivateKey(entry.PrivateKey); err != nil {
				return nil, fmt.Errorf("%s.privateKey: %w", where, err)
			}
			parsed[entry.PrivateKey] = key
		}
		p := &Profile{
			Participant: entry,
			Callback:    cfg.CallbackFor(entry),
			Key:         key,
			Default:     i == 0,
		}
		set.profiles = append(set.profiles, p)
		if code := p.Code(); code != "" {
			set.byCode[strings.ToLower(code)] = p
		}
	}
	return set, nil
}

// Default returns the top-level profile. Never nil for a Set built from a
// validated config.
func (s *Set) Default() *Profile {
	if s == nil || len(s.profiles) == 0 {
		return nil
	}
	return s.profiles[0]
}

// All returns every profile, the default first.
func (s *Set) All() []*Profile {
	if s == nil {
		return nil
	}
	return s.profiles
}

// Len is how many identities this gateway holds.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.profiles)
}

// Hosted reports whether more than the default profile is configured.
func (s *Set) Hosted() bool { return s.Len() > 1 }

// ByCode finds the profile with that registry code, in either spelling and
// case-insensitively. Nil when no profile matches.
func (s *Set) ByCode(code string) *Profile {
	if s == nil {
		return nil
	}
	code = nhcx.NormalizeCode(code)
	if code == "" {
		return nil
	}
	return s.byCode[strings.ToLower(code)]
}

// Resolve returns the profile for code, falling back to the default so a
// message with no usable recipient header is still handled.
func (s *Set) Resolve(code string) *Profile {
	if p := s.ByCode(code); p != nil {
		return p
	}
	return s.Default()
}

// IsLocal reports whether code is one of this gateway's own identities.
func (s *Set) IsLocal(code string) bool { return s.ByCode(code) != nil }

// Codes lists every configured code, the default first.
func (s *Set) Codes() []string {
	out := make([]string, 0, s.Len())
	for _, p := range s.All() {
		if c := p.Code(); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// OwnsKey reports whether pub is one of this gateway's own encryption keys.
// Used to catch a registry answer that hands back our own certificate for
// somebody else: only the recipient can open a JWE, so encrypting with our
// key would put an unreadable payload on the wire.
func (s *Set) OwnsKey(pub *rsa.PublicKey) bool {
	if s == nil || pub == nil {
		return false
	}
	for _, p := range s.profiles {
		if own := p.PublicKey(); own != nil && own.Equal(pub) {
			return true
		}
	}
	return false
}

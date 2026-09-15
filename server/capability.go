package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/claudiodangelis/qrcp/pages"
)

const (
	// authCookieName is the name of the HttpOnly session cookie issued
	// after a successful PIN exchange.
	authCookieName = "qrcp_auth"
	// defaultPINLength is the number of digits of the out-of-band PIN
	// shown on the host's screen.
	defaultPINLength = 6
	// maxPINAttempts is how many wrong PINs are accepted before the
	// capability token is permanently revoked.
	maxPINAttempts = 5
	// defaultCapabilityTTL is the default lifetime of an unredeemed
	// capability token ("short-term" authorization window).
	defaultCapabilityTTL = 3 * time.Minute
	// sessionTTL is how long the exchange session stays valid after
	// the PIN has been verified.
	sessionTTL = 10 * time.Minute
	// tokenBytes is the size, in bytes, of the random capability token
	// encoded in the QR code (256 bits of entropy).
	tokenBytes = 32
)

var (
	errCapabilityExpired  = errors.New("capability token has expired")
	errCapabilityRedeemed = errors.New("capability token has already been redeemed on another device")
	errCapabilityLocked   = errors.New("capability token revoked after too many wrong PINs")
	errInvalidPIN         = errors.New("invalid PIN")
)

// capability is a short-lived, single-use authorization grant.
//
// It implements a two-factor local authorization protocol:
//  1. Possession: a high-entropy random token delivered out-of-band via a
//     QR code ("what the user scanned").
//  2. Knowledge: a short numeric PIN displayed on the host screen and
//     typed on the phone ("what the user sees on the host").
//
// The token can be exchanged exactly once: a successful PIN verification
// redeems it and mints a session cookie bound to the transfer. A leaked
// or photographed QR code alone is therefore useless without the PIN, and
// a successful scan cannot be replayed on a second device.
type capability struct {
	pinHash   []byte
	salt      []byte
	expiresAt time.Time

	mu            sync.Mutex
	attempts      int
	redeemed      bool
	locked        bool
	session       string
	sessionExpiry time.Time
}

// capabilityRegistry stores the outstanding capability tokens keyed by
// their random token string.
type capabilityRegistry struct {
	mu    sync.RWMutex
	items map[string]*capability
}

func newCapabilityRegistry() *capabilityRegistry {
	return &capabilityRegistry{items: make(map[string]*capability)}
}

// issue mints a new capability token protected by pin and valid for ttl.
// The returned token string is safe to embed in a URL path.
func (r *capabilityRegistry) issue(pin string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = defaultCapabilityTTL
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	c := &capability{
		salt:      salt,
		pinHash:   hashPIN(salt, pin),
		expiresAt: time.Now().Add(ttl),
	}
	r.mu.Lock()
	r.items[token] = c
	r.mu.Unlock()
	return token, nil
}

func (r *capabilityRegistry) get(token string) (*capability, bool) {
	r.mu.RLock()
	c, ok := r.items[token]
	r.mu.RUnlock()
	return c, ok
}

// generatePIN returns a cryptographically random length-digit numeric PIN.
// Leading zeroes are preserved.
func generatePIN(length int) (string, error) {
	if length <= 0 {
		length = defaultPINLength
	}
	var b strings.Builder
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}
	return b.String(), nil
}

func hashPIN(salt []byte, pin string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(pin))
	return h.Sum(nil)
}

// Attempts returns the number of failed PIN verifications so far.
func (c *capability) Attempts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts
}

// redeem verifies the PIN and, on success, performs the one-time exchange
// of the capability token for a random session identifier.
func (c *capability) redeem(pin string, now time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.locked:
		return "", errCapabilityLocked
	case !c.redeemed && now.After(c.expiresAt):
		c.locked = true
		return "", errCapabilityExpired
	case c.redeemed:
		// A capability can be exchanged on one device only.
		return "", errCapabilityRedeemed
	}
	if subtle.ConstantTimeCompare(hashPIN(c.salt, pin), c.pinHash) != 1 {
		c.attempts++
		if c.attempts >= maxPINAttempts {
			c.locked = true
			return "", errCapabilityLocked
		}
		return "", errInvalidPIN
	}
	sessionRaw := make([]byte, 40)
	if _, err := rand.Read(sessionRaw); err != nil {
		return "", err
	}
	session := base64.StdEncoding.EncodeToString(sessionRaw)
	c.session = session
	c.sessionExpiry = now.Add(sessionTTL)
	c.redeemed = true
	return session, nil
}

// validateSession checks a session cookie value against this capability.
func (c *capability) validateSession(session string, now time.Time) bool {
	if session == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.redeemed || subtle.ConstantTimeCompare([]byte(session), []byte(c.session)) != 1 {
		return false
	}
	return now.Before(c.sessionExpiry)
}

// pinPageData is passed to the PIN entry template.
type pinPageData struct {
	Route     string
	Next      string
	PINLength int
	Error     string
	Disabled  bool
}

// servePINPage renders the mobile PIN entry form (or a terminal state).
func servePINPage(w http.ResponseWriter, status int, data pinPageData) {
	w.WriteHeader(status)
	serveTemplate("pin", pages.Pin, w, data)
}

// authorizeTransfer gates a transfer route behind the two-factor
// protocol. It returns true when the request carries a valid exchange
// session. Otherwise it renders the PIN entry page (GET) or a plain 401
// (POST uploads) and returns false.
//
// kind is the route kind used to extract the token from the path, either
// "/send" or "/receive".
func authorizeTransfer(w http.ResponseWriter, r *http.Request, registry *capabilityRegistry, kind string) bool {
	token := strings.TrimPrefix(r.URL.Path, kind+"/")
	grant, ok := registry.get(token)
	if !ok {
		http.NotFound(w, r)
		return false
	}
	if cookie, err := r.Cookie(authCookieName); err == nil &&
		grant.validateSession(cookie.Value, time.Now()) {
		return true
	}
	// No valid session: explain why and collect the PIN on GET.
	if r.Method != http.MethodGet {
		http.Error(w, "unauthorized: PIN verification required", http.StatusUnauthorized)
		return false
	}
	now := time.Now()
	grant.mu.Lock()
	// Expiry takes precedence: a token locked because its time window
	// elapsed must read as "expired", not "revoked".
	expired := !grant.redeemed && now.After(grant.expiresAt)
	locked := grant.locked && !expired
	redeemed := grant.redeemed
	sessionExpired := grant.redeemed && now.After(grant.sessionExpiry)
	grant.mu.Unlock()

	data := pinPageData{
		Route:     "/auth/" + token,
		Next:      r.URL.Path,
		PINLength: defaultPINLength,
	}
	switch {
	case expired:
		data.Disabled = true
		data.Error = "This QR code has expired. Generate a new one on the host computer."
		servePINPage(w, http.StatusGone, data)
	case locked:
		data.Disabled = true
		data.Error = "Too many wrong PINs. This QR code has been revoked."
		servePINPage(w, http.StatusForbidden, data)
	case sessionExpired:
		data.Disabled = true
		data.Error = "The transfer session has expired. Generate a new QR code on the host computer."
		servePINPage(w, http.StatusGone, data)
	case redeemed:
		data.Disabled = true
		data.Error = "This transfer has already been unlocked on another device."
		servePINPage(w, http.StatusForbidden, data)
	default:
		servePINPage(w, http.StatusOK, data)
	}
	return false
}

// redeemPINRequest handles the POST that exchanges the capability token
// plus PIN for a session cookie. It is the server side of the /auth
// endpoint.
//
// On success it returns the redirect target and the issued session value;
// the caller is responsible for the final redirect. On failure an error
// page (or plain HTTP error) has already been written and ok is false.
func redeemPINRequest(w http.ResponseWriter, r *http.Request, registry *capabilityRegistry, secure bool) (target, session string, ok bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", "", false
	}
	token := strings.TrimPrefix(r.URL.Path, "/auth/")
	grant, found := registry.get(token)
	if !found {
		http.NotFound(w, r)
		return "", "", false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return "", "", false
	}
	next := r.PostFormValue("next")
	// Accept a path or a same-host absolute URL, but only ever redirect
	// back to this token's own transfer routes.
	target = next
	if u, err := url.Parse(next); err == nil && u.IsAbs() {
		if u.Host != r.Host {
			http.Error(w, "invalid redirect target", http.StatusBadRequest)
			return "", "", false
		}
		target = u.Path
	}
	if target != "/send/"+token && target != "/receive/"+token {
		http.Error(w, "invalid redirect target", http.StatusBadRequest)
		return "", "", false
	}
	pin := r.PostFormValue("pin")
	session, err := grant.redeem(pin, time.Now())
	if err != nil {
		data := pinPageData{
			Route:     "/auth/" + token,
			Next:      target,
			PINLength: defaultPINLength,
		}
		switch {
		case errors.Is(err, errCapabilityExpired):
			data.Disabled = true
			data.Error = "This QR code has expired. Generate a new one on the host computer."
			servePINPage(w, http.StatusGone, data)
		case errors.Is(err, errCapabilityLocked):
			data.Disabled = true
			data.Error = "Too many wrong PINs. This QR code has been revoked."
			servePINPage(w, http.StatusForbidden, data)
		case errors.Is(err, errCapabilityRedeemed):
			data.Disabled = true
			data.Error = "This transfer has already been unlocked on another device."
			servePINPage(w, http.StatusForbidden, data)
		default:
			data.Error = fmt.Sprintf("Incorrect PIN. %d attempt(s) remaining.",
				maxPINAttempts-grant.Attempts())
			servePINPage(w, http.StatusUnauthorized, data)
		}
		return "", "", false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    session,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return target, session, true
}

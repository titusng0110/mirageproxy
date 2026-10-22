package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// HeaderAuthTime and HeaderAuthSig carry the request timestamp and its
	// HMAC signature on every authenticated request.
	HeaderAuthTime = "X-Auth-Time"
	HeaderAuthSig  = "X-Auth-Sig"

	// ParamClientID and ParamRequestID are the query parameters holding the
	// client and request identities.
	ParamClientID  = "clientid"
	ParamRequestID = "requestid"

	// maxAuthSkew bounds how far a signed request's timestamp may drift from
	// the receiver's clock, in seconds, before it is rejected as stale.
	maxAuthSkew = 90
)

// PollID returns the signing identity bound to a client's poll connection;
// UploadID returns the identity covering that client's upload batches (which
// span many concurrent sessions). Both sides must agree on these identities,
// so they live here.
func PollID(clientID string) string   { return "poll-" + clientID }
func UploadID(clientID string) string { return "upload-" + clientID }

// GenerateSignature is the hex-encoded HMAC-SHA256 of "<timestamp>:<id>"
// under secret.
func GenerateSignature(secret string, timestamp int64, id string) string {
	msg := fmt.Sprintf("%d:%s", timestamp, id)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignRequest stamps req with the auth headers bound to id: the current unix
// time in HeaderAuthTime and its signature in HeaderAuthSig.
func SignRequest(req *http.Request, secret, id string) {
	now := time.Now().Unix()
	req.Header.Set(HeaderAuthTime, strconv.FormatInt(now, 10))
	req.Header.Set(HeaderAuthSig, GenerateSignature(secret, now, id))
}

// VerifyAuth checks a request's auth headers against secret and id: both
// headers must be present, the timestamp within maxAuthSkew seconds of the
// local clock, and the signature must match. The error text feeds the
// caller's denial log.
func VerifyAuth(r *http.Request, secret, id string) error {
	timeStr := r.Header.Get(HeaderAuthTime)
	clientSig := r.Header.Get(HeaderAuthSig)
	if timeStr == "" || clientSig == "" {
		return errors.New("Missing or invalid headers")
	}

	clientTime, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return errors.New("Missing or invalid headers")
	}

	now := time.Now().Unix()
	if clientTime < now-maxAuthSkew || clientTime > now+maxAuthSkew {
		return fmt.Errorf("Time skew detected (Client: %d, Server: %d)", clientTime, now)
	}

	if clientSig != GenerateSignature(secret, clientTime, id) {
		return errors.New("Invalid signature")
	}
	return nil
}

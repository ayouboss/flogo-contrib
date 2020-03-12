package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"

	"database/sql"

	_ "github.com/lib/pq"
)

// log is the default package logger
var log = logger.GetLogger("activity-sha1")


// MyActivity is a stub for your Activity implementation
type MyActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new AppActivity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *MyActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval
func (a *MyActivity) Eval(context activity.Context) (done bool, err error) {
	s := context.GetInput(signature)
	p := context.GetInput(payload)
	k := context.GetInput(secretkey)
	// do eval
	validateSignature(s, p, k)

	return true, nil
}

//copied from https://github.com/google/go-github/blob/master/github/messages.go

// genMAC generates the HMAC signature for a message provided the secret key
// and hashFunc.
func genMAC(message, key string, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key string, hashFunc func() hash.Hash) bool {
	expectedMAC := genMAC(message, key, hashFunc)
	return hmac.Equal(messageMAC, expectedMAC)
}

// messageMAC returns the hex-decoded HMAC tag from the signature and its
// corresponding hash function.
func messageMAC(signature string) ([]byte, func() hash.Hash, error) {
	if signature == "" {
		return nil, nil, errors.New("missing signature")
	}
	sigParts := strings.SplitN(signature, "=", 2)
	if len(sigParts) != 2 {
		return nil, nil, fmt.Errorf("error parsing signature %q", signature)
	}

	var hashFunc func() hash.Hash

	hashFunc = sha1.New

	buf, err := hex.DecodeString(sigParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding signature %q: %v", signature, err)
	}
	return buf, hashFunc, nil
}

// ValidateSignature validates the signature for the given payload.
// signature is the Facebook hash signature delivered in the X-Hub-Signature header.
// payload is the JSON payload sent by GitHub Webhooks.
// secretToken is the Facebook Webhook secret token.
//
// Facebook Messenger API docs: https://developers.facebook.com/docs/messenger-platform/webhook/
func validateSignature(signature string, payload, secretToken string) error {
	messageMAC, hashFunc, err := messageMAC(signature)
	if err != nil {
		//return err
		return true, err
	}
	if !checkMAC(payload, messageMAC, secretToken, hashFunc) {
		//return errors.New("payload signature check failed")
		return false, nil
	}
	return nil
}

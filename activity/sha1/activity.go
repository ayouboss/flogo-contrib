package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/project-flogo/core/data/coerce"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

// log is the default package logger
var log = logger.GetLogger("activity-sha1")

const (
	signature = "signature"
	secretkey = "secretkey"
	payload   = "payload"

	ovResult = "validated"
)

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
	
	secret := context.GetInput(secretkey)
	signature := context.GetInput(signature)
	payload := context.GetInput(payload)
	
	
	//err = context.GetInputObject(in)
	//if err != nil {
	//	return false, err
	//}
	
	//err = context.SetOutput(ovValue, bool(val))
	
	result = verifySignature(coerce.ToBytes(secret), coerce.ToString(signature), coerce.ToBytes(payload))
	if err != nil {
		return false, err
	}
	
	//result := "ok"

	//err = context.SetOutput(ovResult, result)

	context.SetOutput(ovResult, result)
	if err != nil {
		return false, err
	}

	return true, nil
}


func signBody(secret, body []byte) []byte {
	computed := hmac.New(sha1.New, secret)
	computed.Write(body)
	return []byte(computed.Sum(nil))
}

func verifySignature(secret []byte, signature string, body []byte) bool {

	const signaturePrefix = "sha1="
	const signatureLength = 45 // len(SignaturePrefix) + len(hex(sha1))

	if len(signature) != signatureLength || !strings.HasPrefix(signature, signaturePrefix) {
		return false
	}

	actual := make([]byte, 20)
	hex.Decode(actual, []byte(signature[5:]))

	return hmac.Equal(signBody(secret, body), actual)
}

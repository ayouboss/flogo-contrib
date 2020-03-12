package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"crypto/subtle"

	//"github.com/project-flogo/core/data/coerce"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

// log is the default package logger
var log = logger.GetLogger("activity-sha1")

const (
	signature = "signature"
	secretkey = "secretkey"
	payload   = "payload"

	validated = "validated"
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
	signature := context.GetInput(signature).(string)
	payload := context.GetInput(payload).(string)
	
	//err = context.GetInputObject(in)
	//if err != nil {
	//	return false, err
	//}
	
	//err = context.SetOutput(ovValue, bool(val))
	
	 
	//if !verifySignature(secret, payload, signature) {
		
	//	context.SetOutput(validated, false)
	//}
	
	//validated := "ok"

	context.SetOutput(validated, verifySignature(secret, payload, signature))

	return true, nil
}


func generateSignature(secretToken, payloadBody string) string {
	mac := hmac.New(sha1.New, []byte(secretToken))
	mac.Write([]byte(payloadBody))
	expectedMAC := mac.Sum(nil)
	return "sha1=" + hex.EncodeToString(expectedMAC)
}

func verifySignature(secretToken, payloadBody string, signatureToCompareWith string) bool {
	
	const signaturePrefix = "sha1="
	const signatureLength = 45 // len(SignaturePrefix) + len(hex(sha1))

	//if len(signatureToCompareWith) != signatureLength || !strings.HasPrefix(signature, signaturePrefix) {
	//	return false
	//}
	
	signature := generateSignature(secretToken, payloadBody)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(signatureToCompareWith)) == 1
}


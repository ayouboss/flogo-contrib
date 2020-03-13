package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"crypto/subtle"
	"encoding/base64"
	"strings"

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
	
	secret := context.GetInput(secretkey).(string)
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
	
	
	log.Info("Verifying Signature")
	log.Info(payload)
	res := verifyFBSignature([]byte(secret), signature ,[]byte(payload))

	context.SetOutput(validated, res)

	return true, nil
}



func signBody(secret, body []byte) []byte {
	computed := hmac.New(sha1.New, secret)
	computed.Write(body)
	
	return []byte(computed.Sum(nil))
}

func verifyFBSignature(secret []byte, signature string, body []byte) bool {

	const signaturePrefix = "sha1="
	const signatureLength = 45 // len(SignaturePrefix) + len(hex(sha1))

	if len(signature) != signatureLength || !strings.HasPrefix(signature, signaturePrefix) {
		return false
	}



	actual := make([]byte, 20)
	hex.Decode(actual, []byte(signature[5:]))
	
	return hmac.Equal(signBody(secret, body), actual)
}



func generateSignature(secretToken, payloadBody string) string {
	mac := hmac.New(sha1.New, []byte(secretToken))
	mac.Write([]byte(payloadBody))
	expectedMAC := mac.Sum(nil)
	return "sha1=" + hex.EncodeToString(expectedMAC)
	//return hex.EncodeToString(expectedMAC)
}

func computeHmac1(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func verifySignature(secretToken, payloadBody string, signatureToCompareWith string) bool {
	
	const signaturePrefix = "sha1="
	const signatureLength = 45 // len(SignaturePrefix) + len(hex(sha1))
	
	log.Info(signatureToCompareWith)

	if len(signatureToCompareWith) != signatureLength || !strings.HasPrefix(signatureToCompareWith, signaturePrefix) {
		return false
	}
	
	signature := generateSignature(secretToken, payloadBody)
	
	log.Info("signature is...")
	log.Info(signature)
	log.Info("signature to compare")
	log.Info(signatureToCompareWith)
	return subtle.ConstantTimeCompare([]byte(signature), []byte(signatureToCompareWith)) == 1
}


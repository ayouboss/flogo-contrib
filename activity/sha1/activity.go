package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	//"errors"
	//"io"
	//"io/ioutil"
	"strings"

	"github.com/project-flogo/contrib/function/coerce"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

// log is the default package logger
var log = logger.GetLogger("activity-sha1")

type Input struct {
	Signature interface{} `md:"signature"`
	Payload interface{} `md:"payload"`
	SecretKey interface{} `md:"secretkey"`
}

type Output struct {
	Value interface{} `md:"value"` // The value of the shared attribute
}

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
	
	in := &Input{}
	err = context.GetInputObject(in)
	if err != nil {
		return false, err
	}
	
	//err = context.SetOutput(ovValue, bool(val))
	
	result = verifySignature(coerce.toBytes(in.SecretKey), in.Signature, in.Payload)
	if err != nil {
		return false, err
	}
	
	err = context.SetOutput(ovResults, in)
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

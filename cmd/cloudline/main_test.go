package main

import (
	"encoding/base64"
	"github.com/kongesque/line-cli/internal/session"
	"strings"
	"testing"
)

func TestEncryptedSessionRoundTripAndTampering(t *testing.T) {
	a, e := cryptor(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if e != nil {
		t.Fatal(e)
	}
	s := &session.State{Version: 1, Generation: "generation", AccessToken: "SECRET", LastReqSeq: 123}
	b, e := seal(a, s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b, "SECRET") {
		t.Fatal("plaintext")
	}
	restored, e := unseal(a, b)
	if e != nil || restored.LastReqSeq != 123 {
		t.Fatal("round trip")
	}
	raw, _ := base64.StdEncoding.DecodeString(b)
	raw[len(raw)-1] ^= 1
	if _, e = unseal(a, base64.StdEncoding.EncodeToString(raw)); e == nil {
		t.Fatal("accepted tampering")
	}
	other, _ := cryptor(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("1", 32))))
	if _, e = unseal(other, b); e == nil {
		t.Fatal("accepted wrong key")
	}
}

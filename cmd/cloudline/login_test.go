package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"

	"github.com/kongesque/line-cli/internal/session"
	"github.com/makiuchi-d/gozxing"
	qrdecoder "github.com/makiuchi-d/gozxing/qrcode"
)

func TestLoginDisplayIsAttemptBoundAndCannotOpenSession(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	a, _ := cryptor(key)
	id := strings.Repeat("a", 32)
	blob, e := sealDisplay(a, id, loginDisplay{Kind: session.QRLoginPIN, PIN: "123456"})
	if e != nil {
		t.Fatal(e)
	}
	event, e := openDisplay(a, id, blob)
	if e != nil || event.PIN != "123456" {
		t.Fatal("round trip failed")
	}
	if _, e = openDisplay(a, strings.Repeat("b", 32), blob); e == nil {
		t.Fatal("cross-attempt replay accepted")
	}
	b, _ := base64.StdEncoding.DecodeString(blob)
	b[len(b)-1] ^= 1
	if _, e = openDisplay(a, id, base64.StdEncoding.EncodeToString(b)); e == nil {
		t.Fatal("tampering accepted")
	}
	sessionBlob, _ := seal(a, &session.State{Version: 1, Generation: "synthetic", AccessToken: "synthetic"})
	if _, e = openDisplay(a, id, sessionBlob); e == nil {
		t.Fatal("session accepted as QR display")
	}
	if _, e = unseal(a, blob); e == nil {
		t.Fatal("QR display accepted as session")
	}
}
func TestReconnectRejectsDifferentAccountBeforeSave(t *testing.T) {
	guard := sameAccount("synthetic-account")
	for _, s := range []*session.State{
		{MID: "other", ExportedKeys: map[string]string{"1": "synthetic"}},
		{MID: "synthetic-account", NoE2EE: true, ExportedKeys: map[string]string{"1": "synthetic"}},
		{MID: "synthetic-account"},
	} {
		if guard(s) == nil {
			t.Fatal("unsafe replacement accepted")
		}
	}
	if guard(&session.State{MID: "synthetic-account", ExportedKeys: map[string]string{"1": "synthetic"}}) != nil {
		t.Fatal("same account rejected")
	}
	var out bytes.Buffer
	store := &pipeStore{validate: guard}
	// No cipher/pipe is configured: a rejected identity must stop before touching either.
	if store.Save(&session.State{MID: "other"}) == nil || out.Len() != 0 {
		t.Fatal("rejected identity reached save")
	}
}
func TestCloudQRPNGDecodesIndependently(t *testing.T) {
	value := "line://au/q/synthetic-only?secret=synthetic&e2eeVersion=1"
	uri, e := qrPNG(value)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "data:image/png;base64,"))
	if e != nil {
		t.Fatal(e)
	}
	img, e := png.Decode(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	bitmap, e := gozxing.NewBinaryBitmapFromImage(img)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := qrdecoder.NewQRCodeReader().Decode(bitmap, nil)
	if e != nil || decoded.GetText() != value {
		t.Fatal("QR does not decode", e)
	}
}

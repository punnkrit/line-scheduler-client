package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"time"

	"github.com/kongesque/line-cli/internal/session"
	qrcode "github.com/yeqown/go-qrcode/v2"
)

// Display ciphertext uses a separate key and attempt-bound AAD. The scheduling
// API can display a QR/PIN but cannot decrypt the stored LINE session.
type loginDisplay struct {
	Kind session.QRLoginEventKind `json:"kind"`
	URL  string                   `json:"url,omitempty"`
	PIN  string                   `json:"pin,omitempty"`
}

func displayAAD(attempt string) ([]byte, error) {
	b, e := hex.DecodeString(attempt)
	if e != nil || len(b) != 16 {
		return nil, errors.New("invalid login attempt")
	}
	return []byte("line-scheduler/qr/v1/" + attempt), nil
}
func sealDisplay(a cipher.AEAD, attempt string, event loginDisplay) (string, error) {
	aad, e := displayAAD(attempt)
	if e != nil {
		return "", e
	}
	p, e := json.Marshal(event)
	if e != nil {
		return "", e
	}
	defer clear(p)
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(a.Seal(nonce, nonce, p, aad)), nil
}
func openDisplay(a cipher.AEAD, attempt, blob string) (loginDisplay, error) {
	var event loginDisplay
	aad, e := displayAAD(attempt)
	if e != nil {
		return event, e
	}
	b, e := base64.StdEncoding.DecodeString(blob)
	if e != nil || len(b) < a.NonceSize()+a.Overhead() || len(b) > 16384 {
		return event, errors.New("invalid display")
	}
	p, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], aad)
	if e != nil {
		return event, errors.New("invalid display")
	}
	defer clear(p)
	e = json.Unmarshal(p, &event)
	return event, e
}
func sameAccount(expected string) func(*session.State) error {
	return func(s *session.State) error {
		if s.MID == "" || s.NoE2EE || len(s.ExportedKeys) == 0 || (expected != "" && s.MID != expected) {
			return errors.New("approved account does not match or lacks encryption")
		}
		return nil
	}
}
func login(r request, a cipher.AEAD, in *json.Decoder, out *json.Encoder) (any, error) {
	displayKey, e := cryptor(r.QRKey)
	if e != nil {
		return nil, e
	}
	if _, e = displayAAD(r.Attempt); e != nil {
		return nil, e
	}
	expected := ""
	if r.Blob != "" {
		old, e := unseal(a, r.Blob)
		if e != nil {
			return nil, e
		}
		if old.MID == "" {
			return nil, errors.New("existing account identity missing")
		}
		expected = old.MID
	}
	store := &pipeStore{aead: a, in: in, out: out, validate: sameAccount(expected)}
	manager := session.NewManager(store)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	_, e = manager.LoginQR(ctx, func(event session.QRLoginEvent) error {
		blob, e := sealDisplay(displayKey, r.Attempt, loginDisplay{Kind: event.Kind, URL: event.URL, PIN: event.PIN})
		if e != nil {
			return e
		}
		if e = out.Encode(map[string]any{"op": "login_event", "blob": blob}); e != nil {
			return e
		}
		var ack struct {
			OK bool `json:"ok"`
		}
		if in.Decode(&ack) != nil || !ack.OK {
			return errors.New("login cancelled")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return map[string]any{"connected": true}, nil
}

type matrixWriter struct{ bitmap [][]bool }

func (w *matrixWriter) Write(m qrcode.Matrix) error { w.bitmap = m.Bitmap(); return nil }
func (*matrixWriter) Close() error                  { return nil }
func qrPNG(value string) (string, error) {
	// Child environment never enables the encoder's debug file output.
	code, e := qrcode.NewWith(value, qrcode.WithEncodingMode(qrcode.EncModeByte), qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionMedium))
	if e != nil {
		return "", errors.New("QR encoding failed")
	}
	m := new(matrixWriter)
	if e = code.Save(m); e != nil {
		return "", errors.New("QR rendering failed")
	}
	const scale = 4
	size := code.Dimension() + 8
	img := image.NewGray(image.Rect(0, 0, size*scale, size*scale))
	for y := 0; y < size*scale; y++ {
		for x := 0; x < size*scale; x++ {
			v := color.Gray{Y: 255}
			mx, my := x/scale-4, y/scale-4
			if mx >= 0 && my >= 0 && mx < code.Dimension() && my < code.Dimension() && m.bitmap[my][mx] {
				v.Y = 0
			}
			img.SetGray(x, y, v)
		}
	}
	var b bytes.Buffer
	if e = png.Encode(&b, img); e != nil {
		return "", e
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes()), nil
}
func loginView(r request) (any, error) {
	a, e := cryptor(r.QRKey)
	if e != nil {
		return nil, e
	}
	event, e := openDisplay(a, r.Attempt, r.Blob)
	if e != nil {
		return nil, e
	}
	result := map[string]any{"kind": event.Kind}
	if event.Kind == session.QRLoginCode {
		if len(event.URL) == 0 || len(event.URL) > 8192 {
			return nil, errors.New("invalid QR")
		}
		result["qr"], e = qrPNG(event.URL)
		if e != nil {
			return nil, e
		}
	}
	if event.Kind == session.QRLoginPIN {
		if len(event.PIN) < 4 || len(event.PIN) > 10 {
			return nil, errors.New("invalid PIN")
		}
		for _, c := range event.PIN {
			if c < '0' || c > '9' {
				return nil, errors.New("invalid PIN")
			}
		}
		result["pin"] = event.PIN
	}
	return result, nil
}

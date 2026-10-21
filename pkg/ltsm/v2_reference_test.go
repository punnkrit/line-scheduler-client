package ltsm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// These are fixed outputs from Python cryptography, using RFC 7748 keys and
// the published LINE v2 algorithm. The generator records the exact references.
// They establish published-algorithm compatibility only, not compatibility with
// Chrome's white-box key/MID transforms or a real account's exported key blob.
type v2ReferenceVector struct {
	Name          string
	PrivateKey    string
	PeerPublicKey string
	SharedSecret  string
	To            string
	Sender        string
	SenderKeyID   int
	ReceiverKeyID int
	ContentType   int
	Sequence      int64
	Plaintext     string
	Salt          string
	Nonce         string
	AAD           string
	AESKey        string
	Ciphertext    string
}

func loadV2References(t *testing.T) []v2ReferenceVector {
	t.Helper()
	data, err := os.ReadFile("testdata/v2_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []v2ReferenceVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 3 {
		t.Fatal("missing independently generated V2 vectors")
	}
	return vectors
}

func referenceHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func referenceChannel(t *testing.T, v v2ReferenceVector) *Channel {
	t.Helper()
	ch, err := NewChannel(referenceHex(t, v.PrivateKey), referenceHex(t, v.PeerPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ch.SharedSecret[:], referenceHex(t, v.SharedSecret)) {
		t.Fatal("X25519 differs from the RFC 7748 shared secret")
	}
	return ch
}

func TestV2IndependentKnownAnswers(t *testing.T) {
	for _, v := range loadV2References(t) {
		t.Run(v.Name, func(t *testing.T) {
			ch := referenceChannel(t, v)
			if !bytes.Equal(buildAADv2(v.To, v.Sender, v.SenderKeyID, v.ReceiverKeyID, v.ContentType), referenceHex(t, v.AAD)) {
				t.Fatal("AAD differs from independent raw-MID/big-endian encoding")
			}
			key := deriveKeyV2(ch.SharedSecret[:], referenceHex(t, v.Salt))
			if !bytes.Equal(key[:], referenceHex(t, v.AESKey)) {
				t.Fatal("key derivation differs from independent SHA-256 result")
			}
			plaintext, err := ch.DecryptV2(v.To, v.Sender, v.SenderKeyID, v.ReceiverKeyID, v.ContentType, referenceHex(t, v.Ciphertext))
			if err != nil || !bytes.Equal(plaintext, referenceHex(t, v.Plaintext)) {
				t.Fatal("could not decrypt Python cryptography known answer")
			}
		})
	}
}

func TestV2OfficialWASMKnownAnswer(t *testing.T) {
	// This ciphertext was produced offline by the unmodified official Chrome
	// 3.7.2 WASM using authenticated synthetic encrypted MIDs, and independently
	// decrypted by Python cryptography before being recorded. The generator
	// includes the pinned original WASM/host-shim hashes and exact instructions.
	data, err := os.ReadFile("testdata/v2_official_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var v v2ReferenceVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ch := referenceChannel(t, v)
	plaintext, err := ch.DecryptV2(v.To, v.Sender, v.SenderKeyID, v.ReceiverKeyID, v.ContentType, referenceHex(t, v.Ciphertext))
	if err != nil || !bytes.Equal(plaintext, referenceHex(t, v.Plaintext)) {
		t.Fatal("could not decrypt independently verified official WASM ciphertext")
	}
	if binary.BigEndian.Uint64(referenceHex(t, v.Nonce)[:8]) != uint64(v.Sequence) {
		t.Fatal("official WASM nonce does not match the full 64-bit fixture counter")
	}
}

func TestV2IndependentEncryptionFraming(t *testing.T) {
	for _, v := range loadV2References(t) {
		t.Run(v.Name, func(t *testing.T) {
			ch := referenceChannel(t, v)
			ciphertext, err := ch.EncryptV2(v.To, v.Sender, v.SenderKeyID, v.ReceiverKeyID, v.ContentType, v.Sequence, referenceHex(t, v.Plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != 44+len(referenceHex(t, v.Plaintext)) {
				t.Fatal("V2 framing must include salt16, nonce12, and tag16")
			}
			if binary.BigEndian.Uint64(ciphertext[16:24]) != uint64(v.Sequence) {
				t.Fatal("V2 nonce lost or reordered the 64-bit chat counter")
			}
			// Use the independent fixture's literal AAD, never buildAADv2 or
			// DecryptV2, to catch matching encrypt/decrypt implementation errors.
			material := append([]byte{}, referenceHex(t, v.SharedSecret)...)
			material = append(material, ciphertext[:16]...)
			material = append(material, []byte("Key")...)
			key := sha256.Sum256(material)
			block, err := aes.NewCipher(key[:])
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, ciphertext[16:28], ciphertext[28:], referenceHex(t, v.AAD))
			if err != nil || !bytes.Equal(plaintext, referenceHex(t, v.Plaintext)) {
				t.Fatal("encrypted output fails the independent fixture's AAD/KDF")
			}
		})
	}
}

func TestV2IndependentAuthenticationRejectsChanges(t *testing.T) {
	v := loadV2References(t)[0]
	ch := referenceChannel(t, v)
	for _, field := range []string{"recipient", "sender", "sender key", "receiver key", "content type", "salt", "nonce", "ciphertext", "tag"} {
		t.Run(field, func(t *testing.T) {
			to, sender, sid, rid, contentType := v.To, v.Sender, v.SenderKeyID, v.ReceiverKeyID, v.ContentType
			data := referenceHex(t, v.Ciphertext)
			switch field {
			case "recipient":
				to = "u1123456789abcdef0123456789abcdef"
			case "sender":
				sender = "u0edcba9876543210fedcba9876543210"
			case "sender key":
				sid++
			case "receiver key":
				rid++
			case "content type":
				contentType++
			case "salt":
				data[0] ^= 1
			case "nonce":
				data[16] ^= 1
			case "ciphertext":
				data[28] ^= 1
			case "tag":
				data[len(data)-1] ^= 1
			}
			plaintext, err := ch.DecryptV2(to, sender, sid, rid, contentType, data)
			if err == nil || len(plaintext) != 0 {
				t.Fatal("changed V2 data or authenticated metadata returned plaintext")
			}
		})
	}
}

func TestV2RejectsNoncanonicalIdentities(t *testing.T) {
	v := loadV2References(t)[0]
	ch := referenceChannel(t, v)
	for name, mid := range map[string]string{
		"empty":            "",
		"short":            v.To[:32],
		"long":             v.To + "0",
		"NUL padded":       v.To[:32] + "\x00",
		"uppercase prefix": "U" + v.To[1:],
		"uppercase hex":    v.To[:1] + strings.ToUpper(v.To[1:]),
		"unknown prefix":   "x" + v.To[1:],
		"invalid hex":      v.To[:32] + "g",
	} {
		t.Run(name, func(t *testing.T) {
			for _, sender := range []bool{false, true} {
				to, from := v.To, v.Sender
				if sender {
					from = mid
				} else {
					to = mid
				}
				if ciphertext, err := ch.EncryptV2(to, from, v.SenderKeyID, v.ReceiverKeyID, v.ContentType, v.Sequence, nil); err == nil || len(ciphertext) != 0 {
					t.Fatal("noncanonical identity produced V2 ciphertext")
				}
				if plaintext, err := ch.DecryptV2(to, from, v.SenderKeyID, v.ReceiverKeyID, v.ContentType, referenceHex(t, v.Ciphertext)); err == nil || len(plaintext) != 0 {
					t.Fatal("noncanonical identity authenticated a canonical-identity fixture")
				}
			}
		})
	}
}

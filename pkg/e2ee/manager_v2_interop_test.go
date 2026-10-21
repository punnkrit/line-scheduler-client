package e2ee

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/kongesque/line-cli/pkg/line"
	"github.com/kongesque/line-cli/pkg/ltsm"
)

// These IDs were generated from repeating synthetic bytes by the public Chrome
// 3.7.2 WASM (SHA256 58bb4e189ab9bbd7d72ed415258da36afd50e306cb019bab75329d4f5f1b65b3).
// They contain no account identities. See docs/V2_COMPATIBILITY.md for provenance.
const (
	syntheticTo            = "uf82zNxJ1lQ3eCrbAgx1X6wbi3745SGfOJfcedryFex4"
	syntheticFrom          = "u7taovmWXRBTY0jhEMCgFt_-Fts6Gd_T0NFMhHwH9tWc"
	syntheticGroup         = "cIrMop-SuN2kN_PQ4SeV8XYhjtrtokedOt4oN5Tczn0k"
	syntheticCanonicalTo   = "u11111111111111111111111111111111"
	syntheticCanonicalFrom = "u22222222222222222222222222222222"
)

func TestManagerV2EncodedMIDInteroperability(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := m.runner.KeyGenerate()
	if err != nil {
		t.Fatal(err)
	}
	public, err := m.runner.KeyGetPublic(sender)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.myKeyID, m.myRawKeyID = sender, 11
	m.RegisterUnwrappedKey(11, sender)
	chunks, err := m.EncryptMessageV2(syntheticTo, syntheticFrom, sender, base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()), 11, 22, 0, "synthetic")
	if err != nil {
		t.Fatalf("V2 manager encryption failed: %v", err)
	}
	msg := &line.Message{To: syntheticTo, From: syntheticFrom, Chunks: chunks, ContentMetadata: map[string]string{"e2eeVersion": "2"}}
	_, ciphertext, err := messageCipher(msg)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ltsm.NewChannel(peer.Bytes(), senderPublic)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := recipient.DecryptV2(syntheticCanonicalTo, syntheticCanonicalFrom, 11, 22, 0, ciphertext)
	if err != nil || string(plaintext) != `{"text":"synthetic"}` {
		t.Fatalf("independent recipient rejected V2: %v", err)
	}
	if text, err := m.DecryptMessageV2(msg); err != nil || text != string(plaintext) {
		t.Fatalf("V2 echo failed: %v", err)
	}
	msg.ContentType = 14
	if text, err := m.DecryptMessageV2(msg); err == nil || text != "" {
		t.Fatal("altered content type authenticated")
	}
	msg.ContentType, msg.To = 0, syntheticFrom
	if text, err := m.DecryptMessageV2(msg); err == nil || text != "" {
		t.Fatal("altered recipient authenticated")
	}
}

func TestManagerGroupV2EncodedMIDRoundTrip(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := m.runner.KeyGenerate()
	if err != nil {
		t.Fatal(err)
	}
	public, err := m.runner.KeyGetPublic(sender)
	if err != nil {
		t.Fatal(err)
	}
	group, err := m.runner.KeyGenerate()
	if err != nil {
		t.Fatal(err)
	}
	m.myKeyID, m.myRawKeyID = sender, 11
	m.peerPublic[11] = public
	m.groupKeys[syntheticGroup] = map[int]int{33: group}
	m.latestGroupKey[syntheticGroup] = 33
	chunks, err := m.EncryptGroupMessageVersion(syntheticGroup, syntheticFrom, 2, "synthetic group")
	if err != nil {
		t.Fatalf("V2 group encryption failed: %v", err)
	}
	msg := &line.Message{From: syntheticFrom, To: syntheticGroup, ToType: 2, Chunks: chunks, ContentMetadata: map[string]string{"e2eeVersion": "2"}}
	text, key, err := m.DecryptGroupMessage(msg, syntheticGroup)
	if err != nil || key != 33 || text != `{"text":"synthetic group"}` {
		t.Fatalf("V2 group roundtrip failed: %v", err)
	}
	msg.From = syntheticTo
	if text, _, err := m.DecryptGroupMessage(msg, syntheticGroup); err == nil || text != "" {
		t.Fatal("altered group sender authenticated")
	}
}

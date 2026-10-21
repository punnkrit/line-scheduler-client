package e2ee

import (
	"encoding/base64"
	"testing"

	"github.com/kongesque/line-cli/pkg/line"
)

// Valid V1 ciphertext must not be accepted as authenticated V2 data. V1 does
// not authenticate the V2 routing/content metadata, even when its MAC is valid.
func TestDecryptRejectsV1DisguisedAsV2(t *testing.T) {
	m, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := m.runner.KeyGenerate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := m.runner.KeyGenerate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := m.runner.KeyGetPublic(peer)
	if err != nil {
		t.Fatal(err)
	}
	m.RegisterUnwrappedKey(11, sender)
	m.myRawKeyID, m.myKeyID = 11, sender
	m.RegisterPeerPublicKey(22, pub)
	channel, err := m.runner.ChannelCreate(sender, pub)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := m.encryptV1Chunks(channel, 11, 22, []byte(`{"text":"synthetic"}`))
	if err != nil {
		t.Fatal(err)
	}
	const direct = "u22222222222222222222222222222222"
	const group = "c22222222222222222222222222222222"
	const from = "u11111111111111111111111111111111"
	// Use the exact same valid channel for the group fixture; no server or
	// account keys are involved in exercising the version dispatcher.
	m.groupKeys[group] = map[int]int{22: sender}
	m.groupSessionChannels[group] = map[int]map[int]int{22: {11: channel}}
	for _, kind := range []string{"direct", "group"} {
		t.Run(kind, func(t *testing.T) {
			msg := &line.Message{From: from, To: direct, Chunks: chunks, ContentMetadata: map[string]string{}}
			decrypt := func() (string, error) { return m.DecryptMessageV2(msg) }
			if kind == "group" {
				msg.To, msg.ToType = group, 2
				decrypt = func() (string, error) { value, _, err := m.DecryptGroupMessage(msg, group); return value, err }
			}
			msg.ContentMetadata["e2eeVersion"] = "1"
			if value, err := decrypt(); err != nil || value != `{"text":"synthetic"}` {
				t.Fatalf("explicit V1 failed: %v", err)
			}
			for _, version := range []string{"2", "", "3", "-1"} {
				msg.ContentMetadata["e2eeVersion"] = version
				if value, err := decrypt(); err == nil || value != "" {
					t.Fatalf("V1 accepted as version %q", version)
				}
			}
		})
	}
}

func TestDecryptRejectsMalformedEnvelopeBeforeRuntime(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	for _, name := range []string{"nil", "missing_chunk", "extra_chunk", "invalid_base64", "short_salt", "short_nonce", "short_tag", "unknown_version"} {
		t.Run(name, func(t *testing.T) {
			msg := &line.Message{Chunks: []string{b64(16), b64(16), b64(12), b64(4), b64(4)}, ContentMetadata: map[string]string{"e2eeVersion": "2"}}
			switch name {
			case "nil":
				msg = nil
			case "missing_chunk":
				msg.Chunks = msg.Chunks[:4]
			case "extra_chunk":
				msg.Chunks = append(msg.Chunks, b64(4))
			case "invalid_base64":
				msg.Chunks[1] = "!"
			case "short_salt":
				msg.Chunks[0] = b64(15)
			case "short_nonce":
				msg.Chunks[2] = b64(11)
			case "short_tag":
				msg.Chunks[1] = b64(15)
			case "unknown_version":
				msg.ContentMetadata["e2eeVersion"] = "3"
			}
			// No runtime exists: malformed input must be rejected at the boundary.
			m := &Manager{}
			if text, err := m.DecryptMessageV2(msg); err == nil || text != "" {
				t.Fatal("direct malformed message accepted")
			}
			if text, _, err := m.DecryptGroupMessage(msg, "synthetic"); err == nil || text != "" {
				t.Fatal("group malformed message accepted")
			}
		})
	}
}

package e2ee

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	gen "github.com/kongesque/line-cli/pkg"
	"github.com/kongesque/line-cli/pkg/line"
	"github.com/kongesque/line-cli/pkg/ltsm"
)

func TestDirectEncryptionV2FailureDoesNotFallBack(t *testing.T) {
	const chat = "u00000000000000000000000000000000"
	const from = "u11111111111111111111111111111111"
	// Reuse a prepared channel with a missing runner handle so V2 fails after
	// preparation. Falling back to V1 would replace the original error with
	// "V1 encrypt failed: unknown channel: -1".
	public := base64.StdEncoding.EncodeToString(append([]byte{9}, make([]byte, 31)...))
	for _, raw := range []bool{false, true} {
		name := "text"
		if raw {
			name = "raw"
		}
		t.Run(name, func(t *testing.T) {
			m := &Manager{
				runner:        &gen.Runner{},
				myRawKeyID:    11,
				peerPublic:    map[int]string{},
				keyByRawID:    map[int]int{},
				channelByPair: map[string]int{"11|22": -1},
				sequence:      map[string]int{},
			}
			var chunks []string
			var err error
			if raw {
				chunks, err = m.EncryptMessageV2Raw(chat, from, 1, public, 11, 22, 14, []byte(`{"synthetic":true}`))
			} else {
				chunks, err = m.EncryptMessageV2(chat, from, 1, public, 11, 22, 0, "synthetic")
			}
			if err == nil || err.Error() != "unknown channel: -1" || chunks != nil {
				t.Fatalf("V2 failure fell back or returned chunks: %v", err)
			}
		})
	}
}

func TestDirectEncryptionGeneratedKeyV2FailsClosed(t *testing.T) {
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
	public, err := m.runner.KeyGetPublic(peer)
	if err != nil {
		t.Fatal(err)
	}
	m.RegisterUnwrappedKey(11, sender)
	chunks, err := m.EncryptMessageV2("u00000000000000000000000000000000", "u11111111111111111111111111111111", sender, public, 11, 22, 0, "synthetic")
	if err == nil || chunks != nil {
		t.Fatal("unsupported generated-key V2 path returned ciphertext")
	}
}

func TestIsFatalLTSMError(t *testing.T) {
	if !isFatalLTSMError(ltsm.ErrAbort) {
		t.Fatal("direct LTSM abort was not classified as fatal")
	}
	if !isFatalLTSMError(fmt.Errorf("decrypt failed: %w", ltsm.ErrAbort)) {
		t.Fatal("wrapped LTSM abort was not classified as fatal")
	}
	if !isFatalLTSMError(fmt.Errorf("V2 failed: %w; V1 fallback failed: %w", errors.New("invalid V2 ciphertext"), ltsm.ErrAbort)) {
		t.Fatal("LTSM abort in a combined fallback error was not classified as fatal")
	}
	if isFatalLTSMError(errors.New("authentication failed")) {
		t.Fatal("ordinary decryption error was classified as fatal")
	}
}

func TestGroupEncryptionV1RoundTrip(t *testing.T) {
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
	const chat = "c00000000000000000000000000000000"
	const from = "u11111111111111111111111111111111"
	m.myKeyID, m.myRawKeyID = sender, 11
	m.peerPublic[11] = public
	m.groupKeys[chat] = map[int]int{33: group}
	m.latestGroupKey[chat] = 33
	chunks, err := m.EncryptGroupMessageVersion(chat, from, 1, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 5 {
		t.Fatal("invalid chunks")
	}
	salt, err := base64.StdEncoding.DecodeString(chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	mac, err := base64.StdEncoding.DecodeString(chunks[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != 8 || len(mac) != 16 {
		t.Fatal("cipher framing is not V1")
	}
	payload, key, err := m.DecryptGroupMessage(&line.Message{From: from, To: chat, ToType: 2, Chunks: chunks, ContentMetadata: map[string]string{"e2eeVersion": "1"}}, chat)
	if err != nil || key != 33 || payload != `{"text":"synthetic"}` {
		t.Fatalf("V1 roundtrip failed: %v", err)
	}
	for _, version := range []int{0, 3, -1} {
		if _, err := m.EncryptGroupMessageVersion(chat, from, version, "synthetic"); err == nil {
			t.Fatal("unsupported version accepted")
		}
	}
	// Force a V2 runner failure after channel preparation. Preserve that error;
	// the former fallback replaced it with a "V1 encrypt failed" error.
	m.groupSessionChannels[chat][33][11] = -1
	if chunks, err := m.EncryptGroupMessageVersion(chat, from, 2, "synthetic"); err == nil || err.Error() != "unknown channel: -1" || chunks != nil {
		t.Fatalf("V2 failure fell back or returned chunks: %v", err)
	}
}

func TestUnwrapGroupSharedKeyReturnsMissingOwnPrivateKey(t *testing.T) {
	manager := &Manager{
		peerPublic: map[int]string{1234: "creator-public-key"},
		keyByRawID: map[int]int{},
	}

	_, err := manager.UnwrapGroupSharedKey("c-group", &line.E2EEGroupSharedKey{
		CreatorKeyID:  1234,
		ReceiverKeyID: 5625926,
	})
	if !errors.Is(err, ErrMissingOwnPrivateKey) {
		t.Fatalf("err = %v, want ErrMissingOwnPrivateKey", err)
	}
}

func TestChannelFromKeyIDsReturnsMissingOwnPrivateKeyWhenPeerKeyKnown(t *testing.T) {
	manager := &Manager{
		peerPublic: map[int]string{1513671: "peer-public-key"},
		keyByRawID: map[int]int{},
	}

	_, err := manager.channelFromKeyIDs(1513671, 5920082)
	if !errors.Is(err, ErrMissingOwnPrivateKey) {
		t.Fatalf("err = %v, want ErrMissingOwnPrivateKey", err)
	}
	if !strings.Contains(err.Error(), "5920082") {
		t.Fatalf("err = %v, want missing key ID in error", err)
	}
}

func TestEncryptGroupMessageRawReturnsGroupKeyNotLoaded(t *testing.T) {
	manager := &Manager{
		sequence:       map[string]int{},
		groupKeys:      map[string]map[int]int{},
		latestGroupKey: map[string]int{},
	}

	_, err := manager.EncryptGroupMessageRaw("c-group", "u-sender", 0, []byte(`{"text":"hello"}`))
	if !errors.Is(err, ErrGroupKeyNotLoaded) {
		t.Fatalf("err = %v, want ErrGroupKeyNotLoaded", err)
	}
}

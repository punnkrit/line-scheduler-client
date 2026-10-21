package ltsm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These authenticated encrypted MIDs were generated offline with the official
// Chrome 3.7.2 WASM (SHA-256 58bb4e189ab9bbd7d72ed415258da36afd50e306cb019bab75329d4f5f1b65b3).
// Their canonical values are u + 16 bytes of 0x11, u + 16 bytes of 0x22,
// and c + 16 bytes of 0x33, respectively. They contain no account data.
// The public LTSM interface takes these encrypted MIDs, whereas the GCM AAD
// contains their canonical 33-byte forms. Plain u + 32-hex strings are not
// valid encrypted MIDs for that interface.
const (
	runtimeV2To    = "uf82zNxJ1lQ3eCrbAgx1X6wbi3745SGfOJfcedryFex4"
	runtimeV2From  = "u7taovmWXRBTY0jhEMCgFt_-Fts6Gd_T0NFMhHwH9tWc"
	runtimeV2Group = "cIrMop-SuN2kN_PQ4SeV8XYhjtrtokedOt4oN5Tczn0k"
)

func newRuntimeV2Channels(t *testing.T) (*Runtime, uint32, uint32) {
	t.Helper()
	rt, err := NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Close)
	makeKey := func() (uint32, []byte) {
		t.Helper()
		key, err := rt.Curve25519KeyGenerate()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rt.Curve25519KeyDestroy(key) })
		pub, err := rt.Curve25519KeyGetPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return key, pub
	}
	a, apub := makeKey()
	b, bpub := makeKey()
	ab, err := rt.Curve25519KeyCreateChannel(a, bpub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := rt.Curve25519KeyCreateChannel(b, apub)
	if err != nil {
		t.Fatal(err)
	}
	return rt, ab, ba
}

func TestRuntimeV2EncryptedMIDRoundtripPreservesCounter(t *testing.T) {
	rt, sender, receiver := newRuntimeV2Channels(t)
	for _, to := range []string{runtimeV2To, runtimeV2Group} {
		for _, seq := range []int64{1, 1<<32 + 7, 0x0102030405060708} {
			plaintext := []byte(`{"text":"synthetic V2 message"}`)
			ciphertext, err := rt.E2EEChannelEncryptV2(sender, to, runtimeV2From, 11, 22, 0, seq, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != len(plaintext)+44 {
				t.Fatal("unexpected V2 salt/nonce/ciphertext/tag framing")
			}
			if binary.BigEndian.Uint64(ciphertext[16:24]) != uint64(seq) {
				t.Fatal("V2 sequence was narrowed before reaching the native i64 invoker")
			}
			decrypted, err := rt.E2EEChannelDecryptV2(receiver, to, runtimeV2From, 11, 22, 0, ciphertext)
			if err != nil || !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("V2 roundtrip failed: %v", err)
			}
		}
	}
}

func TestRuntimeV2AuthenticatesEncryptedMIDsAndEnvelope(t *testing.T) {
	rt, sender, receiver := newRuntimeV2Channels(t)
	plaintext := []byte(`{"text":"authenticated synthetic message"}`)
	ciphertext, err := rt.E2EEChannelEncryptV2(sender, runtimeV2To, runtimeV2From, 11, 22, 0, 1, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	type envelope struct {
		to, from         string
		sender, receiver int
		contentType      int
		ciphertext       []byte
	}
	valid := envelope{runtimeV2To, runtimeV2From, 11, 22, 0, ciphertext}
	mutations := map[string]func(*envelope){
		"recipient":       func(e *envelope) { e.to = runtimeV2Group },
		"sender":          func(e *envelope) { e.from = runtimeV2To },
		"sender key ID":   func(e *envelope) { e.sender++ },
		"receiver key ID": func(e *envelope) { e.receiver++ },
		"content type":    func(e *envelope) { e.contentType++ },
		"MID tag": func(e *envelope) {
			e.to = runtimeV2To[:len(runtimeV2To)-1] + "A"
		},
		"plain MID": func(e *envelope) { e.to = "u11111111111111111111111111111111" },
	}
	for name, offset := range map[string]int{"salt": 0, "nonce": 16, "body": 28, "tag": len(ciphertext) - 1} {
		mutations[name] = func(e *envelope) {
			e.ciphertext = bytes.Clone(e.ciphertext)
			e.ciphertext[offset] ^= 1
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := valid
			mutate(&e)
			accepted := false
			func() {
				defer func() { _ = recover() }() // Native authentication errors may throw.
				_, err := rt.E2EEChannelDecryptV2(receiver, e.to, e.from, e.sender, e.receiver, e.contentType, e.ciphertext)
				accepted = err == nil
			}()
			if accepted {
				t.Fatal("V2 accepted altered authenticated data")
			}
			got, err := rt.E2EEChannelDecryptV2(receiver, valid.to, valid.from, valid.sender, valid.receiver, valid.contentType, valid.ciphertext)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("valid V2 message failed after authentication rejection: %v", err)
			}
		})
	}
}

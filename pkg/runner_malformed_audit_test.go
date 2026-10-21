package line

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kongesque/line-cli/pkg/ltsm"
)

// These bounded probes use only synthetic data and isolated runtime instances.
// Error content is inspected in memory; test failures never print the input.
func TestMalformedRuntimeInputsFailSafely(t *testing.T) {
	const sentinel = "AUDIT_SYNTHETIC_SECRET_MARKER"
	inputs := [][]byte{nil, {0}, bytes.Repeat([]byte{0xff}, 7), bytes.Repeat([]byte{0x42}, 16), bytes.Repeat([]byte{0x42}, 31), bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x42}, 33), bytes.Repeat([]byte{0x42}, 64), bytes.Repeat([]byte{0x42}, 128), []byte(sentinel)}
	for _, method := range []string{"key_load", "login_keychain", "storage_decrypt", "storage_init"} {
		for i, input := range inputs {
			t.Run(fmt.Sprintf("%s/%d", method, i), func(t *testing.T) {
				encoded := base64.StdEncoding.EncodeToString(input)
				stage := "fixture"
				defer func() {
					if recovered := recover(); recovered != nil {
						text := fmt.Sprint(recovered)
						if strings.Contains(text, sentinel) || (len(encoded) >= 24 && strings.Contains(text, encoded)) {
							t.Error("runtime panic echoed synthetic input")
						}
						t.Errorf("uncaught runtime panic during %s of type %T", stage, recovered)
					}
				}()
				var r *Runner
				if strings.HasPrefix(method, "storage_") {
					r = newSigningTestRunner(t)
					t.Cleanup(r.rt.Close)
				} else {
					r = newQRTestRunner(t)
				}
				if r.keyStore == nil {
					r.keyStore = make(map[int]uint32)
					r.nextID = 1
				}
				if strings.HasPrefix(method, "storage_") {
					aes, err := r.rt.AesKeyNew(r.skPtr)
					if err != nil {
						t.Fatal("could not initialize synthetic storage key")
					}
					r.storageKey = aes
				}
				var call func() error
				switch method {
				case "key_load":
					call = func() error {
						id, err := r.KeyLoad(encoded)
						if err != nil && id != 0 {
							t.Error("rejected key load returned a key handle")
						}
						return err
					}
				case "login_keychain":
					lease, err := r.BeginQRLoginKey()
					if err != nil {
						t.Fatal("could not initialize synthetic login lease")
					}
					t.Cleanup(func() { _ = lease.Close() })
					public, err := lease.Generate()
					if err != nil {
						t.Fatal("could not initialize synthetic login key")
					}
					call = func() error {
						keys, err := r.LoginUnwrapKeyChain(public, encoded)
						if err != nil && len(keys) != 0 {
							t.Error("rejected keychain returned partial keys")
						}
						return err
					}

				case "storage_decrypt":
					call = func() error {
						plain, err := r.StorageDecrypt(encoded)
						if err != nil && plain != "" {
							t.Error("rejected storage ciphertext returned partial plaintext")
						}
						return err
					}
				case "storage_init":
					call = func() error { return r.StorageInit(encoded, encoded, encoded) }
				}
				keyCount, nextID := len(r.keyStore), r.nextID
				activeLogin, activeStorage := r.loginCurveKey, r.storageKey
				stage = "probe"
				err := call()
				if err == nil {
					if method != "storage_init" {
						t.Error("malformed input was accepted")
					}
					return
				}
				if strings.Contains(err.Error(), sentinel) || (len(encoded) >= 24 && strings.Contains(err.Error(), encoded)) {
					t.Error("runtime error echoed synthetic input")
				}
				if len(r.keyStore) != keyCount || r.nextID != nextID || r.loginCurveKey != activeLogin || r.storageKey != activeStorage {
					t.Error("rejected input changed registered keys or active credential handles")
				}
				stage = "subsequent operation"
				if strings.HasPrefix(method, "storage_") {
					const fixture = "synthetic post-rejection storage roundtrip"
					cipher, err := r.StorageEncrypt(fixture)
					if err != nil {
						t.Fatal("rejected input prevented subsequent storage encryption")
					}
					plain, err := r.StorageDecrypt(cipher)
					if err != nil || plain != fixture {
						t.Fatal("rejected input changed subsequent storage roundtrip")
					}
				}

				id, err := r.KeyGenerate()
				if err != nil {
					t.Fatal("rejected input prevented subsequent key generation")
				}
				public, err := r.KeyGetPublic(id)
				if err != nil || public == "" {
					t.Fatal("rejected input prevented subsequent public-key access")
				}

			})
		}
	}
}

// A fatal module abort must remain distinguishable without retaining arbitrary
// exception strings that could contain decoded credential bytes.
func TestCredentialRuntimePanicErrorClassification(t *testing.T) {
	const marker = "AUDIT_SYNTHETIC_SECRET_MARKER"
	for _, value := range []any{marker, errors.New(marker), errors.Join(ltsm.ErrAbort, errors.New(marker))} {
		err := credentialRuntimePanicError("test credential operation", value)
		if strings.Contains(err.Error(), marker) {
			t.Fatal("panic conversion retained synthetic secret text")
		}
		cause, _ := value.(error)
		if errors.Is(err, ltsm.ErrAbort) != errors.Is(cause, ltsm.ErrAbort) {
			t.Fatal("panic conversion changed fatal-abort classification")
		}
	}
}

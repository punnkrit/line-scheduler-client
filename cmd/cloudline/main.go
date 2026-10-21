// cloudline is a narrow adapter. stdout is a private pipe, never a log.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/kongesque/line-cli/internal/cli"
	"github.com/kongesque/line-cli/internal/messaging"
	"github.com/kongesque/line-cli/internal/session"
	"io"
	"os"
	"runtime"
	"time"
)

type request struct {
	Action   string `json:"action"`
	Key      string `json:"key"`
	Blob     string `json:"blob"`
	Chat     string `json:"chat"`
	Text     string `json:"text"`
	FileName string `json:"file_name"`
	FileData []byte `json:"file_data"`
	QRKey    string `json:"qr_key"`
	Attempt  string `json:"attempt"`
}
type pipeStore struct {
	state    *session.State
	aead     cipher.AEAD
	in       *json.Decoder
	out      *json.Encoder
	validate func(*session.State) error
}

const aad = "line-scheduler/session/v1"

func cryptor(key string) (cipher.AEAD, error) {
	b, e := base64.StdEncoding.DecodeString(key)
	if e != nil || len(b) != 32 {
		return nil, errors.New("invalid encryption key")
	}
	block, e := aes.NewCipher(b)
	clear(b)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func seal(a cipher.AEAD, s *session.State) (string, error) {
	p, e := json.Marshal(s)
	if e != nil {
		return "", e
	}
	defer clear(p)
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(a.Seal(nonce, nonce, p, []byte(aad))), nil
}
func unseal(a cipher.AEAD, blob string) (*session.State, error) {
	b, e := base64.StdEncoding.DecodeString(blob)
	if e != nil || len(b) < a.NonceSize()+a.Overhead() {
		return nil, errors.New("invalid session")
	}
	p, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(aad))
	if e != nil {
		return nil, errors.New("session authentication failed")
	}
	defer clear(p)
	var s session.State
	if json.Unmarshal(p, &s) != nil || s.AccessToken == "" || s.Generation == "" || s.Version != 1 {
		return nil, errors.New("invalid session")
	}
	return &s, nil
}
func (s *pipeStore) Load() (*session.State, error) {
	if s.state == nil {
		return nil, session.ErrNotFound
	}
	b, _ := json.Marshal(s.state)
	defer clear(b)
	var next session.State
	json.Unmarshal(b, &next)
	return &next, nil
}
func (s *pipeStore) Save(state *session.State) error {
	if s.validate != nil {
		if err := s.validate(state); err != nil {
			return err
		}
	}
	blob, e := seal(s.aead, state)
	if e != nil {
		return e
	}
	if e = s.out.Encode(map[string]any{"op": "save", "blob": blob}); e != nil {
		return e
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if s.in.Decode(&ack) != nil || !ack.OK {
		return errors.New("durable session save failed")
	}
	s.state = state
	return nil
}
func (s *pipeStore) Delete() error { return errors.New("remote deletion unavailable") }
func run(r request, in *json.Decoder, out *json.Encoder) (any, error) {
	if r.Action == "login-view" {
		return loginView(r)
	}
	a, e := cryptor(r.Key)
	if e != nil {
		return nil, e
	}
	r.Key = ""
	if r.Action == "login" {
		return login(r, a, in, out)
	}
	if r.Action == "export" {
		if runtime.GOOS != "windows" {
			return nil, errors.New("migration requires Windows")
		}
		unlock, e := session.Lock()
		if e != nil {
			return nil, e
		}
		defer unlock()
		local := session.KeychainStore{}
		state, e := local.Load()
		if e != nil {
			return nil, e
		}
		if state.Invalidated {
			return nil, errors.New("local session is invalidated; sign in again")
		}
		blob, e := seal(a, state)
		if e != nil {
			return nil, e
		}
		// Disable the local copy first, preventing concurrent refresh and sequences.
		disabled := *state
		disabled.Invalidated = true
		if e = local.Save(&disabled); e != nil {
			return nil, e
		}
		if e = out.Encode(map[string]any{"op": "save", "blob": blob}); e != nil {
			return nil, e
		}
		var ack struct {
			OK bool `json:"ok"`
		}
		if in.Decode(&ack) != nil || !ack.OK {
			return nil, errors.New("migration needs recovery; local copy remains disabled")
		}
		return map[string]any{"migrated": true}, nil
	}
	if r.Action == "probe" {
		store := &pipeStore{aead: a, in: in, out: out}
		err := store.Save(&session.State{Version: 1, Generation: "synthetic", AccessToken: "synthetic", ExportedKeys: map[string]string{}, LastReqSeq: 123})
		return map[string]any{"persisted": err == nil}, err
	}
	s, e := unseal(a, r.Blob)
	if e != nil {
		return nil, e
	}
	store := &pipeStore{state: s, aead: a, in: in, out: out}
	manager := session.NewManager(store)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	switch r.Action {
	case "probe-read":
		if s.Generation != "synthetic" || s.LastReqSeq != 123 {
			return nil, errors.New("invalid probe")
		}
		return map[string]any{"restored": true}, nil
	case "chats":
		var output bytes.Buffer
		app := cli.App{Manager: manager, Context: ctx, In: bytes.NewReader(nil), Out: &output, Err: io.Discard, Lock: func() (func(), error) { return func() {}, nil }}
		if e := app.Run([]string{"chats", "--json", "--details", "--limit", "200"}); e != nil {
			return nil, e
		}
		return json.RawMessage(output.Bytes()), nil
	case "send", "send-file":
		if r.Action == "send-file" {
			if e := (messaging.Attachment{Name: r.FileName, Data: r.FileData}).Validate(); e != nil {
				return nil, e
			}
			defer clear(r.FileData)
		}
		client, e := messaging.New(manager)
		if e != nil {
			return nil, e
		}
		var result *messaging.SendResult
		if r.Action == "send-file" {
			result, e = client.SendFileContext(ctx, r.Chat, messaging.Attachment{Name: r.FileName, Data: r.FileData}, "")
		} else {
			result, e = client.SendContext(ctx, r.Chat, r.Text)
		}
		if e != nil {
			status := "failed"
			var mutation *messaging.MutationError
			if errors.As(e, &mutation) && mutation.Mutation.Attempted {
				status = "unknown"
			}
			return map[string]any{"status": status, "error": "LINE did not confirm delivery. Check LINE before sending again."}, nil
		}
		return map[string]any{"status": "sent", "message_id": result.ID, "encrypted": result.Encrypted}, nil
	case "check":
		if s.Invalidated || s.NoE2EE || len(s.ExportedKeys) == 0 {
			return nil, errors.New("session needs login")
		}
		if _, e := messaging.New(manager); e != nil {
			return nil, e
		}
		return map[string]any{"connected": true}, nil
	default:
		return nil, errors.New("unsupported operation")
	}
}
func main() {
	in := json.NewDecoder(bufio.NewReader(io.LimitReader(os.Stdin, 32<<20)))
	out := json.NewEncoder(os.Stdout)
	var r request
	if in.Decode(&r) != nil {
		out.Encode(map[string]any{"op": "result", "ok": false})
		return
	}
	result, e := run(r, in, out)
	// Never return raw protocol errors or credentials.
	if e != nil {
		out.Encode(map[string]any{"op": "result", "ok": false, "error": "LINE operation unavailable; session or network needs attention."})
		return
	}
	out.Encode(map[string]any{"op": "result", "ok": true, "data": result})
}

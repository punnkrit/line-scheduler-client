package messaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"testing"

	"github.com/kongesque/line-cli/internal/session"
	"github.com/kongesque/line-cli/pkg/line"
)

type photoGroupAPI struct {
	*imageAPI
	messages          []line.Message
	group             int
	missingAt, failAt int
}

func (a *photoGroupAPI) SendMessageContext(ctx context.Context, seq int64, m *line.Message) (*line.Message, error) {
	a.messages = append(a.messages, *m)
	if len(a.messages) == a.failAt {
		return nil, errors.New("lost response")
	}
	receipt, err := a.imageAPI.SendMessageContext(ctx, seq, m)
	if err != nil {
		return receipt, err
	}
	meta := map[string]string{}
	if m.ContentMetadata["GSEQ"] == "1" {
		a.group++
	}
	if m.ContentMetadata["GID"] != "" && len(a.messages) != a.missingAt {
		meta["GID"] = fmt.Sprintf("server-group_%d", 100+a.group)
	}
	return &line.Message{ID: fmt.Sprint(1000 + len(a.messages)), ContentMetadata: meta}, nil
}

func TestPhotoGroupsSplitAndUseConfirmedServerIDs(t *testing.T) {
	for _, count := range []int{1, 2, 10, 11, 20, 21, 50} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c, f, crypto, _ := setup(t, false)
			api := &photoGroupAPI{imageAPI: &imageAPI{fakeAPI: f, flow: 2}}
			c.crypto = &fileCrypto{fakeCrypto: crypto}
			c.Session.NewClient = func(string) session.API { return api }
			images := make([]PreparedImage, count)
			for i := range images {
				images[i] = *imageFixture(t)
			}
			receipts, err := c.SendImagesContext(context.Background(), "u-peer", images)
			if err != nil || len(receipts) != count {
				t.Fatal("batch", err, len(receipts))
			}
			for start := 0; start < count; start += 10 {
				end := min(start+10, count)
				for i := start; i < end; i++ {
					meta := api.messages[i].ContentMetadata
					if end-start == 1 {
						if meta["GID"] != "" {
							t.Fatal("singleton grouped")
						}
						continue
					}
					wantID := "0"
					if i > start {
						wantID = receipts[start].GroupID
					}
					if meta["GID"] != wantID || meta["GSEQ"] != fmt.Sprint(i-start+1) || meta["GTOTAL"] != fmt.Sprint(end-start) {
						t.Fatal("wrong grouping", meta)
					}
				}
			}
		})
	}
}

func TestPhotoGroupsStopOnLostOrMissingReceipt(t *testing.T) {
	for _, missing := range []bool{false, true} {
		c, f, crypto, _ := setup(t, false)
		api := &photoGroupAPI{imageAPI: &imageAPI{fakeAPI: f, flow: 2}}
		if missing {
			api.missingAt = 2
		} else {
			api.failAt = 2
		}
		c.crypto = &fileCrypto{fakeCrypto: crypto}
		c.Session.NewClient = func(string) session.API { return api }
		img := *imageFixture(t)
		receipts, err := c.SendImagesContext(context.Background(), "u-peer", []PreparedImage{img, img, img})
		expected := 1
		if missing {
			expected = 2
		}
		if err == nil || len(receipts) != expected || len(api.messages) != 2 {
			t.Fatal("replayed or continued uncertain group", err, len(receipts))
		}
	}
}

func TestPhotoGroupsValidateBeforeMutations(t *testing.T) {
	c, f, _, store := setup(t, false)
	img := *imageFixture(t)
	for _, g := range []ImageGroup{{ID: "0", Index: 1, Total: 11}, {ID: "0", Index: 2, Total: 2}, {ID: "9", Index: 1, Total: 2}, {ID: "bad token", Index: 2, Total: 2}} {
		if _, err := c.SendGroupedImageContext(context.Background(), "u-peer", img, g); err == nil {
			t.Fatal("invalid group accepted")
		}
	}
	if _, err := c.SendImagesContext(context.Background(), "u-peer", []PreparedImage{img, {}}); err == nil {
		t.Fatal("invalid later photo accepted")
	}
	if f.sends != 0 || f.registrations != 0 || store.state.LastReqSeq != 0 {
		t.Fatal("invalid batch caused mutation")
	}
}

func TestImageCiphertextInvariantAndIndependentBrowserDecryption(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is needed for independent WebCrypto recipient")
	}
	c, f, crypto, _ := setup(t, false)
	api := &imageAPI{fakeAPI: f, flow: 2}
	crypt := &fileCrypto{fakeCrypto: crypto}
	c.crypto = crypt
	c.Session.NewClient = func(string) session.API { return api }
	img := imageFixture(t)
	var previous string
	for range 2 {
		if _, err := c.SendImageContext(context.Background(), "u-peer", *img, ""); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(api.full, api.preview) || bytes.Equal(img.file.Data, img.preview) {
			t.Fatal("photo/preview ciphertext must be identical despite distinct prepared images")
		}
		var payload map[string]string
		if err := json.Unmarshal(crypt.payloadSent, &payload); err != nil {
			t.Fatal(err)
		}
		if previous == payload["keyMaterial"] {
			t.Fatal("key reused across photos")
		}
		previous = payload["keyMaterial"]
		input, _ := json.Marshal(map[string]any{"key": previous, "full": api.full, "preview": api.preview, "expected": img.file.Data})
		cmd := exec.Command(node, "testdata/photo-recipient.cjs")
		cmd.Stdin = bytes.NewReader(input)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("independent recipient failed: %v %s", err, output)
		}
	}
}

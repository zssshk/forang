package toolscheck

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	// pinned：哈希匹配 → ok；内容改动后 → mismatch。
	p := filepath.Join(dir, "pinned")
	_ = os.WriteFile(p, []byte("hello"), 0o644)
	sum := sha256.Sum256([]byte("hello"))
	pinned := hex.EncodeToString(sum[:])
	// unpinned：存在但无 sha256 → unpinned。
	u := filepath.Join(dir, "unpinned")
	_ = os.WriteFile(u, []byte("x"), 0o644)

	m := Manifest{Tools: []Tool{
		{Name: "pinned", Path: "pinned", SHA256: pinned},
		{Name: "unpinned", Path: "unpinned"},
		{Name: "missing", Path: "nope"},
	}}
	got := Check(m, dir)
	if len(got) != 3 {
		t.Fatalf("结果数 %d want 3", len(got))
	}
	if got[0].Status != StatusOK {
		t.Errorf("pinned: %s want ok", got[0].Status)
	}
	if got[1].Status != StatusUnpinned {
		t.Errorf("unpinned: %s want unpinned", got[1].Status)
	}
	if got[2].Status != StatusMissing {
		t.Errorf("missing: %s want missing", got[2].Status)
	}
	// 改内容 → mismatch。
	_ = os.WriteFile(p, []byte("tampered"), 0o644)
	got = Check(m, dir)
	if got[0].Status != StatusMismatch {
		t.Errorf("tampered: %s want mismatch", got[0].Status)
	}
}

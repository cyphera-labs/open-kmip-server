package storage

import (
	"path/filepath"
	"testing"
)

func runStoreTests(t *testing.T, newStore func(t *testing.T) Storage) {
	t.Run("Create", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, err := s.Create("test-key", 0x00000003, 256, 0x0000000C, "test-owner")
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if rec.UID == "" {
			t.Error("expected non-empty UID")
		}
		if rec.Name != "test-key" {
			t.Errorf("name = %q, want %q", rec.Name, "test-key")
		}
		if len(rec.Material) != 32 {
			t.Errorf("material length = %d, want 32", len(rec.Material))
		}
		if rec.State != StatePreActive {
			t.Errorf("state = %d, want PreActive", rec.State)
		}
		if rec.Owner != "test-owner" {
			t.Errorf("owner = %q, want %q", rec.Owner, "test-owner")
		}
	})

	t.Run("Create_invalid_length", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		_, err := s.Create("bad", 0x00000003, -16, 0x0C, "x")
		if err == nil {
			t.Error("expected error for negative length")
		}
		_, err = s.Create("bad", 0x00000003, 99999, 0x0C, "x")
		if err == nil {
			t.Error("expected error for huge length")
		}
	})

	t.Run("Get_existing", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("my-key", 0x00000003, 256, 0x0C, "x")
		got, ok := s.Get(rec.UID)
		if !ok {
			t.Fatal("Get returned not found")
		}
		if got.UID != rec.UID {
			t.Errorf("UID mismatch")
		}
	})

	t.Run("Get_nonexistent", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		_, ok := s.Get("does-not-exist")
		if ok {
			t.Error("expected not found")
		}
	})

	t.Run("Get_destroyed", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("doomed", 0x00000003, 256, 0x0C, "x")
		s.Destroy(rec.UID)
		_, ok := s.Get(rec.UID)
		if ok {
			t.Error("expected not found for destroyed key")
		}
	})

	t.Run("Locate", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		s.Create("find-me", 0x00000003, 256, 0x0C, "x")
		s.Create("find-me", 0x00000003, 128, 0x0C, "x")
		s.Create("other", 0x00000003, 256, 0x0C, "x")
		uids := s.Locate("find-me")
		if len(uids) != 2 {
			t.Errorf("Locate returned %d, want 2", len(uids))
		}
	})

	t.Run("List", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		s.Create("a", 0x00000003, 256, 0x0C, "x")
		s.Create("b", 0x00000003, 256, 0x0C, "x")
		rec3, _ := s.Create("c", 0x00000003, 256, 0x0C, "x")
		s.Destroy(rec3.UID)
		if len(s.List()) != 2 {
			t.Errorf("List returned %d, want 2", len(s.List()))
		}
	})

	t.Run("Activate", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("act", 0x00000003, 256, 0x0C, "x")
		if err := s.Activate(rec.UID); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Get(rec.UID)
		if got.State != StateActive {
			t.Errorf("state = %d, want Active", got.State)
		}
	})

	t.Run("Destroy", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("bye", 0x00000003, 256, 0x0C, "x")
		s.Destroy(rec.UID)
		_, ok := s.Get(rec.UID)
		if ok {
			t.Error("expected not found after destroy")
		}
	})

	t.Run("Register", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec := &KeyRecord{
			Name: "imported", ObjectType: 0x00000002, Algorithm: 0x00000003,
			Length: 256, Material: []byte("0123456789abcdef0123456789abcdef"), UsageMask: 0x0C,
		}
		result, err := s.Register(rec)
		if err != nil {
			t.Fatal(err)
		}
		if result.UID == "" {
			t.Error("expected UID assigned")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("rev", 0x00000003, 256, 0x0C, "x")
		s.Revoke(rec.UID, 1)
		got, ok := s.Get(rec.UID)
		if !ok {
			t.Fatal("key should exist after revoke")
		}
		if got.State != StateCompromised {
			t.Errorf("state = %d, want Compromised", got.State)
		}
	})

	t.Run("Rekey", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("rk", 0x00000003, 256, 0x0C, "x")
		orig := make([]byte, len(rec.Material))
		copy(orig, rec.Material)
		rekeyed, err := s.Rekey(rec.UID)
		if err != nil {
			t.Fatal(err)
		}
		if rekeyed.Version != 2 {
			t.Errorf("version = %d, want 2", rekeyed.Version)
		}
		same := true
		for i := range orig {
			if orig[i] != rekeyed.Material[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("material unchanged after rekey")
		}
	})

	t.Run("Archive_Recover", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("arc", 0x00000003, 256, 0x0C, "x")
		s.Archive(rec.UID)
		got, _ := s.Get(rec.UID)
		if got.State != StateArchived {
			t.Errorf("state = %d, want Archived", got.State)
		}
		s.Recover(rec.UID)
		got, _ = s.Get(rec.UID)
		if got.State != StatePreActive {
			t.Errorf("state = %d, want PreActive after recover", got.State)
		}
	})

	t.Run("DeriveKey", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		src, _ := s.Create("source", 0x00000003, 256, 0x0C, "x")
		derived, err := s.DeriveKey(src.UID, []byte("ctx"), "derived", 256)
		if err != nil {
			t.Fatal(err)
		}
		if derived.UID == src.UID {
			t.Error("derived should have different UID")
		}
		if len(derived.Material) != 32 {
			t.Errorf("derived material = %d bytes, want 32", len(derived.Material))
		}
	})

	t.Run("DeriveKey_too_long", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		src, _ := s.Create("src", 0x00000003, 256, 0x0C, "x")
		_, err := s.DeriveKey(src.UID, []byte("ctx"), "big", 32768)
		if err == nil {
			t.Error("expected error for oversized derive")
		}
	})

	t.Run("CustomAttributes", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		rec, _ := s.Create("attr", 0x00000003, 256, 0x0C, "x")
		s.SetCustomAttribute(rec.UID, "x-tag", "hello")
		attrs, _ := s.GetCustomAttributes(rec.UID)
		if attrs["x-tag"] != "hello" {
			t.Errorf("attr = %q, want hello", attrs["x-tag"])
		}
		s.SetCustomAttribute(rec.UID, "x-tag", "world")
		attrs, _ = s.GetCustomAttributes(rec.UID)
		if attrs["x-tag"] != "world" {
			t.Errorf("attr = %q, want world", attrs["x-tag"])
		}
		s.DeleteCustomAttribute(rec.UID, "x-tag")
		attrs, _ = s.GetCustomAttributes(rec.UID)
		if _, exists := attrs["x-tag"]; exists {
			t.Error("attr should be deleted")
		}
	})
}

func TestMemoryStore(t *testing.T) {
	runStoreTests(t, func(t *testing.T) Storage {
		return NewMemoryStore()
	})
}

func TestSQLiteStore(t *testing.T) {
	runStoreTests(t, func(t *testing.T) Storage {
		s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

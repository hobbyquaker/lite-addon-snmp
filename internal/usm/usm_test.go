package usm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 3414 §A.3.2: SHA, "maplesyrup", engine 00…02.
func TestRFC3414Vector(t *testing.T) {
	ku := PasswordToKey(SHA1, "maplesyrup")
	if hex.EncodeToString(ku) != "9fb5cc0381497b3793528939ff788d5d79145211" {
		t.Fatalf("Ku %x", ku)
	}
	eng, _ := hex.DecodeString("000000000000000000000002")
	if kul := Localize(SHA1, ku, eng); hex.EncodeToString(kul) != "6695febc9288e36282235fc7151f128497b38f3f" {
		t.Fatalf("Kul %x", kul)
	}
}

func TestDigestAndCipher(t *testing.T) {
	for _, a := range Auths {
		k := LocalKeys(a, AES256, PasswordToKey(a, "authpassword1"), PasswordToKey(a, "privpassword1"), []byte{0x80, 0, 0x1f, 0x88, 5, 1, 2, 3})
		if len(k.PrivKey) != 32 {
			t.Fatalf("%s: priv key %d bytes", a, len(k.PrivKey))
		}
		msg := append([]byte("header"), make([]byte, a.DigestLen())...)
		msg = append(msg, []byte("tail")...)
		Sign(a, k.AuthKey, msg, 6)
		if err := Verify(a, k.AuthKey, msg, 6, msg[6:6+a.DigestLen()]); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		msg[0] ^= 1
		if Verify(a, k.AuthKey, msg, 6, msg[6:6+a.DigestLen()]) == nil {
			t.Fatalf("%s: a changed message verified", a)
		}
		salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		ct, _ := Encrypt(k.PrivKey, 3, 100, salt, []byte("scoped pdu"))
		pt, _ := Decrypt(k.PrivKey, 3, 100, salt, ct)
		if !bytes.Equal(pt, []byte("scoped pdu")) {
			t.Fatalf("%s: round trip %q", a, pt)
		}
	}
	for _, s := range []string{"sha", "SHA1", "sha-256", "SHA512"} {
		if _, err := ParseAuth(s); err != nil {
			t.Error(err)
		}
	}
	if _, err := ParseAuth("MD5"); err == nil {
		t.Error("MD5 accepted")
	}
	if _, err := ParsePriv("DES"); err == nil {
		t.Error("DES accepted")
	}
}

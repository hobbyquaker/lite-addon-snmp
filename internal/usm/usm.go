// Package usm is the cryptography of SNMPv3's user-based security model: the password-to-key
// algorithm and key localisation (RFC 3414 §A.2), HMAC authentication with SHA-1 (RFC 3414) and
// the SHA-2 family (RFC 7860), and AES-CFB privacy (RFC 3826) with 128-bit keys and, as net-snmp's
// "AES-256", 256-bit keys extended by the Blumenthal draft's rule.
package usm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Auth is an authentication protocol.
type Auth string

// Priv is a privacy protocol.
type Priv string

// The protocols the agent offers. MD5 and DES are deliberately absent.
const (
	SHA1   Auth = "SHA"
	SHA224 Auth = "SHA-224"
	SHA256 Auth = "SHA-256"
	SHA384 Auth = "SHA-384"
	SHA512 Auth = "SHA-512"

	AES128 Priv = "AES"
	AES192 Priv = "AES-192"
	AES256 Priv = "AES-256"
)

// Auths lists the authentication protocols, the default first.
var Auths = []Auth{SHA256, SHA1, SHA224, SHA384, SHA512}

// Privs lists the privacy protocols, the default first.
var Privs = []Priv{AES128, AES192, AES256}

// ParseAuth accepts the protocol names in their usual spellings (SHA, SHA1, SHA-256, SHA256, …).
func ParseAuth(s string) (Auth, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "SHA", "SHA1":
		return SHA1, nil
	case "SHA224":
		return SHA224, nil
	case "SHA256":
		return SHA256, nil
	case "SHA384":
		return SHA384, nil
	case "SHA512":
		return SHA512, nil
	}
	return "", fmt.Errorf("unknown authentication protocol %q", s)
}

// ParsePriv accepts AES, AES128, AES-192, AES-256 and the like.
func ParsePriv(s string) (Priv, error) {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "AES", "AES128":
		return AES128, nil
	case "AES192":
		return AES192, nil
	case "AES256":
		return AES256, nil
	}
	return "", fmt.Errorf("unknown privacy protocol %q", s)
}

func (a Auth) newHash() func() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New
	case SHA224:
		return sha256.New224
	case SHA256:
		return sha256.New
	case SHA384:
		return sha512.New384
	case SHA512:
		return sha512.New
	}
	return nil
}

// Valid tells whether the protocol is known.
func (a Auth) Valid() bool { return a.newHash() != nil }

// DigestLen is the length of the truncated MAC carried in msgAuthenticationParameters.
func (a Auth) DigestLen() int {
	switch a {
	case SHA1:
		return 12
	case SHA224:
		return 16
	case SHA256:
		return 24
	case SHA384:
		return 32
	case SHA512:
		return 48
	}
	return 0
}

// KeyLen is the length of the protocol's hash output: the key's length.
func (a Auth) KeyLen() int {
	if h := a.newHash(); h != nil {
		return h().Size()
	}
	return 0
}

// Valid tells whether the protocol is known.
func (p Priv) Valid() bool { return p.KeyLen() > 0 }

// KeyLen is the AES key length.
func (p Priv) KeyLen() int {
	switch p {
	case AES128:
		return 16
	case AES192:
		return 24
	case AES256:
		return 32
	}
	return 0
}

// PasswordToKey is RFC 3414 §A.2's Ku: the hash over one megabyte of the repeated password.
func PasswordToKey(a Auth, password string) []byte {
	nh := a.newHash()
	if nh == nil || password == "" {
		return nil
	}
	h := nh()
	pw := []byte(password)
	buf := make([]byte, 64)
	idx := 0
	for count := 0; count < 1048576; count += 64 {
		for i := range buf {
			buf[i] = pw[idx%len(pw)]
			idx++
		}
		h.Write(buf)
	}
	return h.Sum(nil)
}

// Localize is Kul = H(Ku || engineID || Ku).
func Localize(a Auth, ku, engineID []byte) []byte {
	h := a.newHash()()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// PrivKey is the localised privacy key for the cipher: the localised key, extended by the
// Blumenthal rule (Kul || H(Kul) || H(Kul || H(Kul)) …) where the cipher needs more than the
// hash gives, then cut to the cipher's length.
func PrivKey(a Auth, p Priv, kulPriv []byte) []byte {
	need := p.KeyLen()
	k := append([]byte(nil), kulPriv...)
	for len(k) < need {
		h := a.newHash()()
		h.Write(k)
		k = append(k, h.Sum(nil)...)
	}
	return k[:need]
}

// Digest is the truncated HMAC of a whole message whose authentication parameters are zero.
func Digest(a Auth, kulAuth, msg []byte) []byte {
	m := hmac.New(a.newHash(), kulAuth)
	m.Write(msg)
	return m.Sum(nil)[:a.DigestLen()]
}

// Sign writes the digest into a message at the placeholder's offset (the placeholder must be
// DigestLen zero bytes).
func Sign(a Auth, kulAuth, msg []byte, at int) {
	d := Digest(a, kulAuth, msg)
	copy(msg[at:at+len(d)], d)
}

// ErrDigest is a message whose digest does not verify.
var ErrDigest = errors.New("wrong digest")

// Verify checks a received message's digest: the parameters at the offset are compared after
// computing the HMAC over a copy with them zeroed.
func Verify(a Auth, kulAuth, msg []byte, at int, params []byte) error {
	if len(params) != a.DigestLen() || at < 0 || at+len(params) > len(msg) {
		return ErrDigest
	}
	c := append([]byte(nil), msg...)
	for i := 0; i < len(params); i++ {
		c[at+i] = 0
	}
	if subtle.ConstantTimeCompare(Digest(a, kulAuth, c), params) != 1 {
		return ErrDigest
	}
	return nil
}

// iv is RFC 3826's IV: the authoritative engine's boots and time, then the 64-bit salt.
func iv(boots, time int64, salt []byte) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:], uint32(boots))
	binary.BigEndian.PutUint32(b[4:], uint32(time))
	copy(b[8:], salt)
	return b
}

// Encrypt encrypts a scoped PDU with AES-CFB.
func Encrypt(key []byte, boots, time int64, salt, plain []byte) ([]byte, error) {
	if len(salt) != 8 {
		return nil, errors.New("salt must be 8 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	//lint:ignore SA1019 RFC 3826 is CFB; there is no other way to speak it
	cipher.NewCFBEncrypter(blk, iv(boots, time, salt)).XORKeyStream(out, plain) //nolint:staticcheck
	return out, nil
}

// ErrDecrypt is a message whose privacy parameters are malformed.
var ErrDecrypt = errors.New("decryption error")

// Decrypt decrypts with AES-CFB.
func Decrypt(key []byte, boots, time int64, salt, ct []byte) ([]byte, error) {
	if len(salt) != 8 {
		return nil, ErrDecrypt
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	//lint:ignore SA1019 RFC 3826 is CFB
	cipher.NewCFBDecrypter(blk, iv(boots, time, salt)).XORKeyStream(out, ct) //nolint:staticcheck
	return out, nil
}

// Keys are a user's keys localised to one engine.
type Keys struct {
	Auth    Auth
	Priv    Priv
	AuthKey []byte // Kul for the HMAC
	PrivKey []byte // the cipher key; nil without privacy
}

// LocalKeys localises a user's Ku pair to an engine.
func LocalKeys(a Auth, p Priv, kuAuth, kuPriv, engineID []byte) Keys {
	k := Keys{Auth: a, Priv: p, AuthKey: Localize(a, kuAuth, engineID)}
	if p != "" && len(kuPriv) > 0 {
		k.PrivKey = PrivKey(a, p, Localize(a, kuPriv, engineID))
	}
	return k
}

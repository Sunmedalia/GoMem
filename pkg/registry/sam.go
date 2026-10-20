package registry

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"unicode/utf16"
)

// SAMUser is one local account from a SAM hive. Err is set when that record
// cannot be decoded. LM and NT are lowercase hex; a nil hash in the baseline
// becomes the standard empty digest rather than a blank string.
type SAMUser struct {
	Name      string
	NameKnown bool
	RID       uint32
	LM        string
	NT        string
	Cell      uint64
	Err       error
}

var (
	bootKeyPerm = [16]int{0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7}
	aqwerty     = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	anum        = []byte("0123456789012345678901234567890123456789\x00")
	antpassword = []byte("NTPASSWORD\x00")
	almpassword = []byte("LMPASSWORD\x00")
	emptyLM     = []byte{0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee}
	emptyNT     = []byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0}
)

// DumpSAM reads ControlSet001's LSA class data and the SAM account keys.
// A missing hive, boot key, or user record returns an error. Empty LM/NT
// digests are only used when the baseline would substitute them.
func DumpSAM(ctx context.Context, system, sam *Hive) ([]SAMUser, error) {
	if system == nil {
		return nil, fmt.Errorf("SYSTEM hive is absent")
	}
	if sam == nil {
		return nil, fmt.Errorf("SAM hive is absent")
	}
	boot, err := bootKey(ctx, system)
	if err != nil {
		return nil, err
	}
	hboot, err := hbootKey(ctx, sam, boot)
	if err != nil {
		return nil, err
	}
	usersKey, err := sam.FindKey(ctx, `SAM\Domains\Account\Users`)
	if err != nil {
		return nil, fmt.Errorf("SAM user list: %w", err)
	}
	subs, subErr := sam.Subkeys(ctx, usersKey)
	var users []SAMUser
	var errs []error
	if subErr != nil {
		errs = append(errs, subErr)
	}
	for _, key := range subs {
		if err = ctx.Err(); err != nil {
			return users, err
		}
		if key.Name == "Names" {
			continue
		}
		user := decodeSAMUser(ctx, sam, key, hboot)
		users = append(users, user)
		if user.Err != nil {
			errs = append(errs, user.Err)
		}
	}
	if len(users) == 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("SAM user list is empty"))
	}
	return users, errors.Join(errs...)
}

func bootKey(ctx context.Context, system *Hive) ([]byte, error) {
	const base = `ControlSet001\Control\Lsa`
	parts := make([]byte, 0, 64)
	for _, name := range []string{"JD", "Skew1", "GBG", "Data"} {
		key, err := system.FindKey(ctx, base+`\`+name)
		if err != nil {
			return nil, fmt.Errorf("LSA key %s: %w", name, err)
		}
		class, err := system.ClassData(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("LSA key %s class: %w", name, err)
		}
		text, err := utf16LE(class)
		if err != nil {
			return nil, fmt.Errorf("LSA key %s class: %w", name, err)
		}
		parts = append(parts, text...)
	}
	raw, err := hex.DecodeString(string(parts))
	if err != nil {
		return nil, fmt.Errorf("boot key class data: %w", err)
	}
	if len(raw) != len(bootKeyPerm) {
		return nil, fmt.Errorf("boot key is %d bytes", len(raw))
	}
	out := make([]byte, len(raw))
	for i, src := range bootKeyPerm {
		out[i] = raw[src]
	}
	return out, nil
}

func hbootKey(ctx context.Context, sam *Hive, boot []byte) ([]byte, error) {
	if len(boot) != 16 {
		return nil, fmt.Errorf("boot key is %d bytes", len(boot))
	}
	key, err := sam.FindKey(ctx, `SAM\Domains\Account`)
	if err != nil {
		return nil, fmt.Errorf("SAM account key: %w", err)
	}
	data, err := namedValue(ctx, sam, key, "F")
	if err != nil {
		return nil, fmt.Errorf("SAM account F: %w", err)
	}
	return hbootFromF(data, boot)
}

func hbootFromF(data, boot []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("SAM account F is empty")
	}
	switch data[0] {
	case 2:
		if len(data) < 0xA0 {
			return nil, fmt.Errorf("SAM account F revision 2 is %d bytes", len(data))
		}
		sum := md5.New()
		sum.Write(data[0x70:0x80])
		sum.Write(aqwerty)
		sum.Write(boot)
		sum.Write(anum)
		return rc4Apply(sum.Sum(nil), data[0x80:0xA0])
	case 3:
		if len(data) < 0xA8 {
			return nil, fmt.Errorf("SAM account F revision 3 is %d bytes", len(data))
		}
		plain, err := aesCBC(boot, data[0x78:0x88], data[0x88:0xA8])
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), plain[:16]...), nil
	default:
		return nil, fmt.Errorf("SAM account F revision %d is not supported", data[0])
	}
}

func decodeSAMUser(ctx context.Context, sam *Hive, key Key, hboot []byte) SAMUser {
	user := SAMUser{Cell: key.Address}
	rid, err := strconv.ParseUint(key.Name, 16, 32)
	if err != nil {
		user.Err = fmt.Errorf("SAM user key %q is not a RID", key.Name)
		return user
	}
	user.RID = uint32(rid)
	data, err := namedValue(ctx, sam, key, "V")
	if err != nil {
		user.Err = fmt.Errorf("SAM user %s V: %w", key.Name, err)
		return user
	}
	if len(data) < 0xB0 {
		user.Err = fmt.Errorf("SAM user %s V is %d bytes", key.Name, len(data))
		return user
	}
	lmOff := int(binary.LittleEndian.Uint32(data[0x9C:0xA0])) + 0xCC
	lmLen := binary.LittleEndian.Uint32(data[0xA0:0xA4])
	ntOff := int(binary.LittleEndian.Uint32(data[0xA8:0xAC])) + 0xCC
	ntLen := binary.LittleEndian.Uint32(data[0xAC:0xB0])
	lm, err := oneHash(data, lmOff, lmLen, user.RID, hboot, almpassword, false)
	if err != nil {
		user.Err = fmt.Errorf("SAM user %s LM: %w", key.Name, err)
		return user
	}
	nt, err := oneHash(data, ntOff, ntLen, user.RID, hboot, antpassword, true)
	if err != nil {
		user.Err = fmt.Errorf("SAM user %s NT: %w", key.Name, err)
		return user
	}
	if lm == nil {
		lm = emptyLM
	}
	if nt == nil {
		nt = emptyNT
	}
	user.LM = hex.EncodeToString(lm)
	user.NT = hex.EncodeToString(nt)
	nameRel := int(binary.LittleEndian.Uint32(data[0x0C:0x10])) + 0xCC
	nameLen := int(binary.LittleEndian.Uint32(data[0x10:0x14]))
	if nameLen < 0 || nameLen > len(data) || nameRel < 0 || nameRel > len(data) || nameRel+nameLen > len(data) {
		return user
	}
	raw := data[nameRel : nameRel+nameLen]
	if len(raw)%2 != 0 {
		raw = raw[:len(raw)-1]
	}
	text, err := utf16LE(raw)
	if err != nil {
		return user
	}
	user.Name = string(text)
	user.NameKnown = true
	return user
}

// oneHash follows the pinned baseline. NT revision 2 reads its salt at
// nt_offset+8, not +4. A revision or length the baseline ignores returns a nil
// hash so the caller can substitute the empty digest.
func oneHash(data []byte, at int, length uint32, rid uint32, hboot, lmnt []byte, nt bool) ([]byte, error) {
	if at < 0 || at+3 > len(data) {
		return nil, fmt.Errorf("hash header at %d outside %d-byte value", at, len(data))
	}
	switch data[at+2] {
	case 1:
		if length != 20 {
			return nil, nil
		}
		if at+20 > len(data) {
			return nil, fmt.Errorf("hash ciphertext exceeds value")
		}
		return decryptRC4Hash(rid, hboot, data[at+4:at+20], lmnt)
	case 2:
		if length != 56 {
			return nil, nil
		}
		saltAt, encAt := at+4, at+20
		if nt {
			saltAt, encAt = at+8, at+24
		}
		if saltAt < 0 || encAt < 0 || saltAt+16 > len(data) || encAt+32 > len(data) {
			return nil, fmt.Errorf("salted hash exceeds value")
		}
		return decryptAESHash(rid, hboot, data[encAt:encAt+32], data[saltAt:saltAt+16])
	default:
		return nil, nil
	}
}

func decryptRC4Hash(rid uint32, hboot, enc, lmnt []byte) ([]byte, error) {
	if len(hboot) < 16 || len(enc) != 16 {
		return nil, fmt.Errorf("RC4 hash input is incomplete")
	}
	sum := md5.New()
	sum.Write(hboot[:16])
	var ridLE [4]byte
	binary.LittleEndian.PutUint32(ridLE[:], rid)
	sum.Write(ridLE[:])
	sum.Write(lmnt)
	obf, err := rc4Apply(sum.Sum(nil), enc)
	if err != nil {
		return nil, err
	}
	return decryptDESHash(rid, obf)
}

func decryptAESHash(rid uint32, hboot, enc, salt []byte) ([]byte, error) {
	if len(hboot) < 16 || len(enc) != 32 || len(salt) != aes.BlockSize {
		return nil, fmt.Errorf("AES hash input is incomplete")
	}
	plain, err := aesCBC(hboot[:16], salt, enc)
	if err != nil {
		return nil, err
	}
	return decryptDESHash(rid, plain[:16])
}

func decryptDESHash(rid uint32, obf []byte) ([]byte, error) {
	if len(obf) < 16 {
		return nil, fmt.Errorf("DES hash is %d bytes", len(obf))
	}
	k1, k2 := sidToKeys(rid)
	left, err := desDecrypt(k1, obf[:8])
	if err != nil {
		return nil, err
	}
	right, err := desDecrypt(k2, obf[8:16])
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func sidToKeys(rid uint32) ([]byte, []byte) {
	b := []byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	s1 := []byte{b[0], b[1], b[2], b[3], b[0], b[1], b[2]}
	s2 := []byte{b[3], b[0], b[1], b[2], b[3], b[0], b[1]}
	return sidBytesToKey(s1), sidBytesToKey(s2)
}

func sidBytesToKey(s []byte) []byte {
	key := []byte{
		s[0] >> 1,
		((s[0] & 0x01) << 6) | (s[1] >> 2),
		((s[1] & 0x03) << 5) | (s[2] >> 3),
		((s[2] & 0x07) << 4) | (s[3] >> 4),
		((s[3] & 0x0F) << 3) | (s[4] >> 5),
		((s[4] & 0x1F) << 2) | (s[5] >> 6),
		((s[5] & 0x3F) << 1) | (s[6] >> 7),
		s[6] & 0x7F,
	}
	for i := range key {
		key[i] = oddParity(key[i] << 1)
	}
	return key
}

func oddParity(b byte) byte {
	b &^= 1
	if bits.OnesCount8(b)%2 == 0 {
		b |= 1
	}
	return b
}

func rc4Apply(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func aesCBC(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES ciphertext is %d bytes", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func desDecrypt(key, block []byte) ([]byte, error) {
	c, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(block))
	c.Decrypt(out, block)
	return out, nil
}

func namedValue(ctx context.Context, h *Hive, key Key, name string) ([]byte, error) {
	values, err := h.Values(ctx, key)
	for _, value := range values {
		if value.Name != name {
			continue
		}
		if value.DataErr != nil {
			return nil, value.DataErr
		}
		return value.Data, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("value %s not found", name)
}

func utf16LE(raw []byte) (string, error) {
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("utf-16 length %d is odd", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(units)), nil
}

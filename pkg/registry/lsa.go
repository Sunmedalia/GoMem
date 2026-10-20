package registry

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// LSASecret is one Policy\Secrets CurrVal. Err is set when that secret cannot
// be decrypted. Data is the baseline plaintext, including Vista block padding.
type LSASecret struct {
	Name      string
	NameKnown bool
	Data      []byte
	Cell      uint64
	Err       error
}

// CachedCredential is one NL$ cache entry. Hash is the leading decrypted
// digest, which the baseline renders as bytes rather than a trimmed string.
type CachedCredential struct {
	Username   string
	Domain     string
	DomainName string
	Hash       []byte
	Value      string
	Cell       uint64
	Err        error
}

// DumpLSA decrypts SECURITY secrets with the SYSTEM boot key. Vista or later
// selects PolEKList and the independent AES blocks; earlier Windows selects
// PolSecretEncryptionKey and SystemFunction005. A missing hive, boot key, LSA
// key, or secret value returns an error. Empty output is not success.
func DumpLSA(ctx context.Context, system, security *Hive, vistaOrLater bool) ([]LSASecret, error) {
	lsakey, err := prepareLSA(ctx, system, security, vistaOrLater)
	if err != nil {
		return nil, err
	}
	secretsKey, err := security.FindKey(ctx, `Policy\Secrets`)
	if err != nil {
		return nil, fmt.Errorf("LSA secrets key: %w", err)
	}
	subs, subErr := security.Subkeys(ctx, secretsKey)
	var out []LSASecret
	var errs []error
	if subErr != nil {
		errs = append(errs, subErr)
	}
	for _, key := range subs {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		item := LSASecret{Name: key.Name, NameKnown: true, Cell: key.Address}
		data, decErr := secretByName(ctx, security, key.Name, lsakey, vistaOrLater)
		if decErr != nil {
			item.Err = fmt.Errorf("LSA secret %s: %w", key.Name, decErr)
			errs = append(errs, item.Err)
		} else {
			item.Data = data
		}
		out = append(out, item)
	}
	if len(out) == 0 && len(errs) == 0 {
		errs = append(errs, fmt.Errorf("LSA secret list is empty"))
	}
	return out, errors.Join(errs...)
}

// DumpCache decrypts NL$ cache entries. NL$Control and slots with a zero user
// length or an empty IV are skipped, matching the baseline. A readable cache
// that contains only those slots succeeds with no rows. A missing hive, boot
// key, LSA key, NL$KM, or Cache key fails.
func DumpCache(ctx context.Context, system, security *Hive, vistaOrLater bool) ([]CachedCredential, error) {
	lsakey, err := prepareLSA(ctx, system, security, vistaOrLater)
	if err != nil {
		return nil, err
	}
	nlkm, err := secretByName(ctx, security, "NL$KM", lsakey, vistaOrLater)
	if err != nil {
		return nil, fmt.Errorf("NL$KM: %w", err)
	}
	if len(nlkm) == 0 || vistaOrLater && len(nlkm) < 32 {
		return nil, fmt.Errorf("NL$KM is %d bytes", len(nlkm))
	}
	cacheKey, err := security.FindKey(ctx, "Cache")
	if err != nil {
		return nil, fmt.Errorf("cache key: %w", err)
	}
	values, valErr := security.Values(ctx, cacheKey)
	var out []CachedCredential
	var errs []error
	if valErr != nil {
		errs = append(errs, valErr)
	}
	for _, value := range values {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		if value.Name == "NL$Control" {
			continue
		}
		item := CachedCredential{Value: value.Name, Cell: value.Address}
		if value.DataErr != nil {
			item.Err = fmt.Errorf("cache value %s: %w", value.Name, value.DataErr)
			errs = append(errs, item.Err)
			out = append(out, item)
			continue
		}
		parsed, skip, parseErr := parseCacheEntry(value.Data)
		if parseErr != nil {
			item.Err = fmt.Errorf("cache value %s: %w", value.Name, parseErr)
			errs = append(errs, item.Err)
			out = append(out, item)
			continue
		}
		if skip {
			continue
		}
		plain, decErr := decryptCachedHash(parsed.enc, nlkm, parsed.iv, !vistaOrLater)
		if decErr != nil {
			item.Err = fmt.Errorf("cache value %s: %w", value.Name, decErr)
			errs = append(errs, item.Err)
			out = append(out, item)
			continue
		}
		item.Username, item.Domain, item.DomainName, item.Hash = parseDecryptedCache(plain, parsed.userLen, parsed.domainLen, parsed.dnsLen)
		out = append(out, item)
	}
	return out, errors.Join(errs...)
}

func prepareLSA(ctx context.Context, system, security *Hive, vistaOrLater bool) ([]byte, error) {
	if system == nil {
		return nil, fmt.Errorf("SYSTEM hive is absent")
	}
	if security == nil {
		return nil, fmt.Errorf("SECURITY hive is absent")
	}
	boot, err := BootKey(ctx, system)
	if err != nil {
		return nil, err
	}
	return lsaKey(ctx, security, boot, vistaOrLater)
}

func lsaKey(ctx context.Context, security *Hive, boot []byte, vistaOrLater bool) ([]byte, error) {
	name := `Policy\PolSecretEncryptionKey`
	if vistaOrLater {
		name = `Policy\PolEKList`
	}
	key, err := security.FindKey(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("LSA policy %s: %w", name[len("Policy\\"):], err)
	}
	enc, err := firstValueData(ctx, security, key)
	if err != nil {
		return nil, fmt.Errorf("LSA policy %s: %w", name[len("Policy\\"):], err)
	}
	if vistaOrLater {
		plain, err := decryptAESLSA(enc, boot)
		if err != nil {
			return nil, fmt.Errorf("LSA policy PolEKList: %w", err)
		}
		if len(plain) < 100 {
			return nil, fmt.Errorf("LSA policy PolEKList decrypts to %d bytes", len(plain))
		}
		return append([]byte(nil), plain[68:100]...), nil
	}
	if len(enc) < 76 {
		return nil, fmt.Errorf("LSA policy PolSecretEncryptionKey is %d bytes", len(enc))
	}
	sum := md5.New()
	sum.Write(boot)
	salt := enc[60:76]
	for i := 0; i < 1000; i++ {
		sum.Write(salt)
	}
	plain, err := rc4Apply(sum.Sum(nil), enc[12:60])
	if err != nil {
		return nil, err
	}
	if len(plain) < 0x20 {
		return nil, fmt.Errorf("LSA policy PolSecretEncryptionKey decrypts to %d bytes", len(plain))
	}
	return append([]byte(nil), plain[0x10:0x20]...), nil
}

func secretByName(ctx context.Context, security *Hive, name string, lsakey []byte, vistaOrLater bool) ([]byte, error) {
	key, err := security.FindKey(ctx, `Policy\Secrets\`+name+`\CurrVal`)
	if err != nil {
		return nil, err
	}
	enc, err := firstValueData(ctx, security, key)
	if err != nil {
		return nil, err
	}
	if vistaOrLater {
		return decryptAESLSA(enc, lsakey)
	}
	if len(enc) < 0xC {
		return nil, fmt.Errorf("secret ciphertext is %d bytes", len(enc))
	}
	return decryptSecret(enc[0xC:], lsakey)
}

// decryptAESLSA follows the pinned Vista path. SHA-256 absorbs the key once
// and secret[28:60] one thousand times. Each 16-byte block from offset 60 is
// decrypted with a fresh zero IV, so the blocks are independent. A short final
// block is an error; the baseline raises TypeError there.
func decryptAESLSA(secret, key []byte) ([]byte, error) {
	if len(secret) < 60 {
		return nil, fmt.Errorf("LSA AES blob is %d bytes", len(secret))
	}
	sum := sha256.New()
	sum.Write(key)
	salt := secret[28:60]
	for i := 0; i < 1000; i++ {
		sum.Write(salt)
	}
	enc := secret[60:]
	if len(enc) == 0 || len(enc)%16 != 0 {
		return nil, fmt.Errorf("LSA AES ciphertext is %d bytes", len(enc))
	}
	return aesECB(sum.Sum(nil), enc)
}

// decryptSecret is the pinned SystemFunction005. The DES key window advances
// by seven bytes. When fewer than seven remain, the next index becomes that
// remainder rather than wrapping to zero. The first four decrypted bytes are
// the payload length; an oversized length is truncated to the buffer.
func decryptSecret(secret, key []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("DES secret is empty")
	}
	decrypted := make([]byte, 0, len(secret)+8)
	j := 0
	for i := 0; i < len(secret); i += 8 {
		blockKey := keyWindow(key, j, 7)
		if len(blockKey) != 7 {
			return nil, fmt.Errorf("DES key window at %d is %d bytes", j, len(blockKey))
		}
		desKey := sidBytesToKey(blockKey)
		enc := secret[i:]
		if len(enc) > 8 {
			enc = enc[:8]
		}
		if len(enc) < 8 {
			padded := make([]byte, 8)
			copy(padded, enc)
			enc = padded
		}
		plain, err := desDecrypt(desKey, enc)
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, plain...)
		j += 7
		if window := keyWindow(key, j, 7); len(window) < 7 {
			j = len(window)
		}
	}
	if len(decrypted) < 4 {
		return nil, fmt.Errorf("decrypted secret is %d bytes", len(decrypted))
	}
	n := int(binary.LittleEndian.Uint32(decrypted[:4]))
	if len(decrypted) < 8 {
		return []byte{}, nil
	}
	end := 8 + n
	if end > len(decrypted) {
		end = len(decrypted)
	}
	if end < 8 {
		end = 8
	}
	return append([]byte(nil), decrypted[8:end]...), nil
}

func decryptCachedHash(edata, nlkm, iv []byte, xp bool) ([]byte, error) {
	if xp {
		mac := hmac.New(md5.New, nlkm)
		mac.Write(iv)
		return rc4Apply(mac.Sum(nil), edata)
	}
	if len(nlkm) < 32 {
		return nil, fmt.Errorf("NL$KM is %d bytes", len(nlkm))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("cache IV is %d bytes", len(iv))
	}
	if len(edata) == 0 {
		return []byte{}, nil
	}
	buf := edata
	if rem := len(buf) % 16; rem != 0 {
		padded := make([]byte, len(buf)+16-rem)
		copy(padded, buf)
		buf = padded
	}
	return aesCBC(nlkm[16:32], iv, buf)
}

type parsedCache struct {
	userLen, domainLen, dnsLen int
	enc, iv                    []byte
}

func parseCacheEntry(data []byte) (parsedCache, bool, error) {
	if len(data) < 4 {
		return parsedCache{}, false, fmt.Errorf("cache entry is %d bytes", len(data))
	}
	entry := parsedCache{
		userLen:   int(binary.LittleEndian.Uint16(data[:2])),
		domainLen: int(binary.LittleEndian.Uint16(data[2:4])),
	}
	if len(data) < 60 {
		return entry, true, nil
	}
	if len(data) < 62 {
		return parsedCache{}, false, fmt.Errorf("cache domain name length is truncated")
	}
	entry.dnsLen = int(binary.LittleEndian.Uint16(data[60:62]))
	if len(data) < 64 {
		return entry, true, nil
	}
	ivEnd := 80
	if len(data) < ivEnd {
		ivEnd = len(data)
	}
	entry.iv = append([]byte(nil), data[64:ivEnd]...)
	if entry.userLen == 0 || len(entry.iv) == 0 {
		return entry, true, nil
	}
	if len(data) > 96 {
		entry.enc = append([]byte(nil), data[96:]...)
	} else {
		entry.enc = []byte{}
	}
	return entry, false, nil
}

func parseDecryptedCache(dec []byte, userLen, domainLen, dnsLen int) (string, string, string, []byte) {
	if userLen < 0 {
		userLen = 0
	}
	if domainLen < 0 {
		domainLen = 0
	}
	if dnsLen < 0 {
		dnsLen = 0
	}
	n := 16
	if n > len(dec) {
		n = len(dec)
	}
	hash := append([]byte(nil), dec[:n]...)
	userOff := 72
	domainOff := userOff + userLen + userLen%4
	dnsOff := domainOff + domainLen + domainLen%4
	return utf16Replace(sliceAt(dec, userOff, userLen)), utf16Replace(sliceAt(dec, domainOff, domainLen)), utf16Replace(sliceAt(dec, dnsOff, dnsLen)), hash
}

func firstValueData(ctx context.Context, h *Hive, key Key) ([]byte, error) {
	values, err := h.Values(ctx, key)
	if len(values) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("key has no values")
	}
	if values[0].DataErr != nil {
		return nil, values[0].DataErr
	}
	return values[0].Data, nil
}

func aesECB(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, fmt.Errorf("AES ciphertext is %d bytes", len(data))
	}
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += 16 {
		// A fresh zero IV makes each block independent, matching the baseline.
		block, err := aesCBC(key, make([]byte, 16), data[i:i+16])
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out, nil
}

func keyWindow(key []byte, at, n int) []byte {
	if at < 0 || at >= len(key) || n <= 0 {
		return nil
	}
	end := at + n
	if end > len(key) {
		end = len(key)
	}
	return key[at:end]
}

func sliceAt(b []byte, off, n int) []byte {
	if off < 0 || n <= 0 || off >= len(b) {
		return nil
	}
	end := off + n
	if end > len(b) {
		end = len(b)
	}
	return b[off:end]
}

func utf16Replace(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	odd := len(raw)%2 != 0
	if odd {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	text := string(utf16.Decode(units))
	if odd {
		text += "\uFFFD"
	}
	return text
}

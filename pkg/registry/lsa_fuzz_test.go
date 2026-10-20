package registry

import "testing"

func FuzzLSABlobs(f *testing.F) {
	f.Add([]byte("abcdefghijklmnop"), []byte("0123456789abcdef"))
	f.Fuzz(func(t *testing.T, blob, key []byte) {
		_, _ = decryptAESLSA(blob, key)
		_, _ = decryptSecret(blob, key)
		_, _, _ = parseCacheEntry(blob)
		_, _ = decryptCachedHash(blob, append(append([]byte{}, key...), key...), key, false)
		_, _ = decryptCachedHash(blob, key, key, true)
		_, _, _, _ = parseDecryptedCache(blob, len(blob)%32, len(key)%32, len(blob)%24)
	})
}

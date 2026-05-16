package tcpx

import (
	"crypto/hmac"
	"crypto/sha256"
)

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(t)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

func hkdfKey(salt, ikm, info []byte) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), info, 32)
}

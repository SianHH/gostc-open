package utils

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5 MD5加密
func MD5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// MD5AndSalt MD5+Salt加密
func MD5AndSalt(str, salt string) (s string) {
	for i := 0; i < 2; i++ {
		s += MD5(str + salt)
	}
	return
}

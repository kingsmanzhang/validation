package validation

import (
	"crypto/md5"
	"fmt"
	"io"
)

func hashMD5(str, encryptSalt string) string {
	hash := md5.New()
	io.WriteString(hash, str)
	pwmd5 := fmt.Sprintf("%x", hash.Sum(nil))
	io.WriteString(hash, encryptSalt)
	io.WriteString(hash, "V.Zhang")
	io.WriteString(hash, pwmd5)
	return fmt.Sprintf("%x", hash.Sum(nil))
}
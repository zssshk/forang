// secret_crypto.go 是凭据/会话类 secret 的 AES-GCM 加解密公共 helper
// （v0.6.3 artex-ymh 移植：取自上游 db/sessions.go 的同款实现，FORANG 本无
// session 子系统，故独立成文件供 credentials.go 使用）。
//
// 格式：gcm1:<base64(nonce|ciphertext)>。密钥由 jwt.key 经 SHA-256 域分离派生
// （见 CredentialSecretKey），密钥缺失时加解密直接报错，绝不明文落库。
package db

import (
	"crypto/aes"
	"crypto/cipher"
)

// secretPrefix 标记密文格式版本：gcm1:<base64(nonce|ciphertext)>。
const secretPrefix = "gcm1:"

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// nilIfZero 把 0 转成 NULL（可空外键列）。
func nilIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

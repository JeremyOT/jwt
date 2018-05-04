package jwt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// ErrInvalidSignature is returned when a token's signature does
// not match its payload.
var ErrInvalidSignature = errors.New("Invalid signature")

// Base64Encoding is the encoding used for serialized tokens.
var Base64Encoding = base64.URLEncoding.WithPadding('.')

// Tokenizer creates and loads data from JWT(ish) tokens.
type Tokenizer struct {
	// SigningKey is a 32 byte key used to sign the token.
	SigningKey []byte
	// EncryptionKey if specified, should be a 32 byte key used
	// to encrypt token data. If not specified, the token will
	// be unencrypted Base64 text.
	EncryptionKey []byte
}

// New returns a new Tokenizer
func New(signingKey []byte, encryptionKey []byte) *Tokenizer {
	return &Tokenizer{
		SigningKey:    signingKey,
		EncryptionKey: encryptionKey,
	}
}

// Pad pads data to the proper block size for encryption.
func Pad(data []byte) []byte {
	padSize := aes.BlockSize - len(data)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, padding...)
}

// Unpad removes padding added by Pad.
func Unpad(data []byte) []byte {
	l := len(data)
	return data[:(l - int(data[l-1]))]
}

// Tokenize stores token data in a JWT token.
func (t *Tokenizer) Tokenize(token interface{}) (payload string, err error) {
	jwt, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, t.SigningKey)
	mac.Write(jwt)
	messageMAC := mac.Sum(nil)
	signedToken := append(messageMAC, jwt...)
	if t.EncryptionKey != nil {
		block, err := aes.NewCipher(t.EncryptionKey)
		if err != nil {
			return "", err
		}
		signedToken = Pad(signedToken)
		cipherText := make([]byte, len(signedToken)+aes.BlockSize)
		iv := cipherText[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}
		encrypter := cipher.NewCBCEncrypter(block, iv)
		encrypter.CryptBlocks(cipherText[aes.BlockSize:], signedToken)
		signedToken = cipherText
	}
	payload = Base64Encoding.EncodeToString(signedToken)
	return
}

// Load reads a JWT token into the supplied token interface.
func (t *Tokenizer) Load(payload string, token interface{}) (err error) {
	signedToken, err := Base64Encoding.DecodeString(payload)
	if err != nil {
		return err
	}
	if t.EncryptionKey != nil {
		block, err := aes.NewCipher(t.EncryptionKey)
		if err != nil {
			return err
		}
		decrypter := cipher.NewCBCDecrypter(block, signedToken[:aes.BlockSize])
		decrypted := make([]byte, len(signedToken)-aes.BlockSize)
		decrypter.CryptBlocks(decrypted, signedToken[aes.BlockSize:])
		if int(decrypted[len(decrypted)-1]) > 16 {
			return ErrInvalidSignature
		}
		signedToken = Unpad(decrypted)
	}
	messageMAC := signedToken[:sha256.Size]
	jwt := signedToken[sha256.Size:]
	mac := hmac.New(sha256.New, t.SigningKey)
	mac.Write(jwt)
	if !hmac.Equal(messageMAC, mac.Sum(nil)) {
		return ErrInvalidSignature
	}
	return json.Unmarshal(jwt, token)
}

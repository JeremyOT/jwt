package jwt

import (
	"testing"
	"time"
)

type TestToken struct {
	UserName  string
	Timestamp int64
}

func TestTokenizer(t *testing.T) {
	token := TestToken{
		UserName:  "test",
		Timestamp: time.Now().Unix(),
	}
	tokenizer := New([]byte("01234567890123456789012345678912"), nil)
	payload, err := tokenizer.Tokenize(&token)
	if err != nil {
		t.Fatalf("Tokenize Failed: %v", err)
	}
	var loadedToken TestToken
	err = tokenizer.Load(payload, &loadedToken)
	if err != nil {
		t.Fatalf("Load Failed: %v", err)
	}
	if loadedToken.UserName != token.UserName {
		t.Error(loadedToken.UserName, "!=", token.UserName)
	}
	if loadedToken.Timestamp != token.Timestamp {
		t.Error(loadedToken.Timestamp, "!=", token.Timestamp)
	}
}

func TestTokenizerBadSignature(t *testing.T) {
	token := TestToken{
		UserName:  "test",
		Timestamp: time.Now().Unix(),
	}
	tokenizer := New([]byte("01234567890123456789012345678912"), nil)
	payload, err := tokenizer.Tokenize(&token)
	if err != nil {
		t.Fatalf("Tokenize Failed: %v", err)
	}
	var loadedToken TestToken
	tokenizer = New([]byte("89012345678901234567890123456789"), nil)
	err = tokenizer.Load(payload, &loadedToken)
	if err != ErrInvalidSignature {
		t.Fatal("Expected invalid signature")
	}
}

func TestEncryptedTokenizer(t *testing.T) {
	token := TestToken{
		UserName:  "test",
		Timestamp: time.Now().Unix(),
	}
	tokenizer := New([]byte("01234567890123456789012345678912"), []byte("89012345678901234567890123456789"))
	payload, err := tokenizer.Tokenize(&token)
	if err != nil {
		t.Fatalf("Tokenize Failed: %v", err)
	}
	var loadedToken TestToken
	err = tokenizer.Load(payload, &loadedToken)
	if err != nil {
		t.Fatalf("Load Failed: %v", err)
	}
	if loadedToken.UserName != token.UserName {
		t.Error(loadedToken.UserName, "!=", token.UserName)
	}
	if loadedToken.Timestamp != token.Timestamp {
		t.Error(loadedToken.Timestamp, "!=", token.Timestamp)
	}
}

func TestEncryptedTokenizerBadKey(t *testing.T) {
	token := TestToken{
		UserName:  "test",
		Timestamp: time.Now().Unix(),
	}
	tokenizer := New([]byte("01234567890123456789012345678912"), []byte("89012345678901234567890123456789"))
	payload, err := tokenizer.Tokenize(&token)
	if err != nil {
		t.Fatalf("Tokenize Failed: %v", err)
	}
	var loadedToken TestToken
	tokenizer = New([]byte("01234567890123456789012345678912"), []byte("01234567890123456789012345678912"))
	err = tokenizer.Load(payload, &loadedToken)
	if err != ErrInvalidSignature {
		t.Fatal("Expected invalid signature")
	}
}

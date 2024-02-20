package test

import (
	"RSA-alg/internal/lib/decrypter"
	"RSA-alg/internal/lib/encrypter"
	"RSA-alg/internal/lib/keys/generator"
	"bytes"
	"testing"
)

// Шифрование с помощью нашей функции, расшифровка с помощью нашей функции
func TestEncryptDecryptReversible(t *testing.T) {
	pub, priv, err := generator.GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Проверка наших щифратора и дешифратора")
	c, err := encrypter.EncryptRSA(pub, msg)

	p, err := decrypter.DecryptRSA(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(p, msg) != 0 {
		t.Errorf("Должно быть: p == msg, получили: p = %v, msg = %v", p, msg)
	}
}

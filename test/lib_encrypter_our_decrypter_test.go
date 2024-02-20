package test

import (
	"RSA-alg/internal/lib/decrypter"
	"RSA-alg/internal/lib/keys/generator"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Шифрование с помощью библиотеной функции rsa.EncryptPKCS1v15, расшифровка с помощью нашей функции
func TestEncryptWithStdlibThenDecrypt(t *testing.T) {
	pub, priv, err := generator.GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	var pubLib rsa.PublicKey
	pubLib.N = pub.N
	pubLib.E = int(pub.E.Int64())

	msg := []byte("Проверка нашего дешифратора")
	c, err := rsa.EncryptPKCS1v15(rand.Reader, &pubLib, msg)
	if err != nil {
		t.Fatal(err)
	}

	p, err := decrypter.DecryptRSA(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(p, msg) != 0 {
		t.Errorf("Должно быть: p == msg, получили: p = %v, msg = %v", p, msg)
	}
}

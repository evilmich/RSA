package test

import (
	"RSA-alg/internal/lib/encrypter"
	"RSA-alg/internal/lib/keys/generator"
	"bytes"
	"crypto/rsa"
	"testing"
)

// Шифрование с помощью нашей функции, расшифровка с помощью библиотеной функции rsa.DecryptPKCS1v15
func TestEncryptThenDecryptWithStdlib(t *testing.T) {
	pub, priv, err := generator.GenerateKeys(1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Проверка нашего шифратора")
	c, err := encrypter.EncryptRSA(pub, msg)

	var privLib rsa.PrivateKey
	privLib.N = pub.N
	privLib.E = int(pub.E.Int64())
	privLib.D = priv.D

	p, err := rsa.DecryptPKCS1v15(nil, &privLib, c)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(p, msg) != 0 {
		t.Errorf("Должно быть: p == msg, получили: p = %v, msg = %v", p, msg)
	}
}

package test

import (
	"RSA-alg/internal/lib/keys/generator"
	"testing"
)

// Проверка генерации ключей: публичного и секретного
func TestGenerateKeys(t *testing.T) {
	pub, priv, err := generator.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("Нужен публичный ключ длинной = 2048, получен длинной =  %v", pub.N.BitLen())
	}
	if priv.N.BitLen() != 2048 {
		t.Errorf("Нужен секретный ключ длинной = 2048, получен длинной = %v", priv.N.BitLen())
	}
}

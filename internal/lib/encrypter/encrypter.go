package encrypter

import (
	"RSA-alg/internal/lib/keys"
	"crypto/rand"
	"fmt"
	"math/big"
)

// encrypt выполняет шифрование сообщения m с использованием открытого ключа и возвращает зашифрованное сообщение.
func encrypt(pub *keys.PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	c.Exp(m, pub.E, pub.N)
	return c
}

// EncryptRSA шифрует сообщение m с использованием открытого ключа pub и возвращает
// зашифрованные байты. Длина m должна быть <= size_in_bytes(длина открытого ключа) - 11,
// в противном случае возвращается ошибка. Формат блока шифрования основан на PKCS #1 v1.5 (RFC 2313).
func EncryptRSA(pub *keys.PublicKey, m []byte) ([]byte, error) {
	// Вычисление длины ключа в байтах, округляя в большую сторону.
	keyLen := (pub.N.BitLen() + 7) / 8
	if len(m) > keyLen-11 {
		return nil, fmt.Errorf("длина сообщения = %v, слишком много", len(m))
	}

	// Согласно RFC 2313, для шифрования рекомендуется использовать тип блока 02:
	// EB = 00 || 02 || PS || 00 || D
	psLen := keyLen - len(m) - 3
	eb := make([]byte, keyLen)
	eb[0] = 0x00
	eb[1] = 0x02

	// Заполняем PS случайными ненулевыми байтами.
	for i := 2; i < 2+psLen; {
		_, err := rand.Read(eb[i : i+1])
		if err != nil {
			return nil, err
		}
		if eb[i] != 0x00 {
			i++
		}
	}
	eb[2+psLen] = 0x00

	// Копируем сообщение m в оставшуюся часть блока шифрования.
	copy(eb[3+psLen:], m)

	// Теперь блок шифрования завершен и мы принимаем его как m-байтовый big.Int,
	// зашифрованный с помощью публичного RSA-ключа.
	mNum := new(big.Int).SetBytes(eb)
	c := encrypt(pub, mNum)

	// В результате получается big.Int, который мы хотим преобразовать в байтовый срез длины keyLen.
	// Весьма вероятно, что размер c в байтах равен keyLen,
	// но в редких случаях нам может потребоваться дополнить его слева нулями.
	// (это происходит только в том случае, если старший бит c равен нулям,
	// что означает, что он более чем в 256 раз меньше, чем модуль).
	padLen := keyLen - len(c.Bytes())
	for i := 0; i < padLen; i++ {
		eb[i] = 0x00
	}
	copy(eb[padLen:], c.Bytes())
	return eb, nil
}

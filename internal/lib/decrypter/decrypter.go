package decrypter

import (
	"RSA-alg/internal/lib/keys"
	"bytes"
	"fmt"
	"math/big"
)

// decrypt выполняет расшифровку c с использованием закрытого ключа и возвращает расшифрованное сообщение.
func decrypt(priv *keys.PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, priv.D, priv.N)
	return m
}

// DecryptRSA расшифровывает сообщение c с помощью закрытого ключа priv и возвращает
// расшифрованные байты на основе блока 02 из PKCS #1 v1.5 (RCS 2313).
// Он ожидает, что длина закрытого ключа в байтах будет равна len(eb) по модулю.
func DecryptRSA(priv *keys.PrivateKey, c []byte) ([]byte, error) {
	keyLen := (priv.N.BitLen() + 7) / 8
	if len(c) != keyLen {
		return nil, fmt.Errorf("длина зашифрованного сообщения = %v, длина ключа = %v", len(c), keyLen)
	}

	// Преобразуем c в big.Int и дешифруем его с помощью закрытого ключа.
	cNum := new(big.Int).SetBytes(c)
	mNum := decrypt(priv, cNum)

	// Запишите байты mnum в m, при необходимости заполняя их слева.
	m := make([]byte, keyLen)
	copy(m[keyLen-len(mNum.Bytes()):], mNum.Bytes())

	// Ожидаем правильного начала блока 02.
	if m[0] != 0x00 {
		return nil, fmt.Errorf("m[0]=%v, нужно 0x00", m[0])
	}
	if m[1] != 0x02 {
		return nil, fmt.Errorf("m[1]=%v, нужно 0x02", m[1])
	}

	// Пропускаем случайное заполнение, пока не будет достигнут байт 0x00.
	// '+2' в записи нужно для возврата индекса слайса.
	endPad := bytes.IndexByte(m[2:], 0x00) + 2
	if endPad < 2 {
		return nil, fmt.Errorf("конец заполненного слайса не найден")
	}

	return m[endPad+1:], nil
}

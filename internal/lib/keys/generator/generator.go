package generator

import (
	"RSA-alg/internal/lib/keys"
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateKeys генерирует пару открытого и закрытого ключей для шифрования/дешифрования с заданным bitLen
func GenerateKeys(bitLen int) (*keys.PublicKey, *keys.PrivateKey, error) {
	numRetries := 0

	for {
		numRetries++
		if numRetries == 10 {
			panic("повторилось слишком много раз, что-то не так")
		}

		// Нам нужен результат pq с b битами, поэтому мы генерируем p и q с b/2 битами каждый.
		// Если установлен старший бит p и q, результат будет содержать b битов.
		// В противном случае мы повторим попытку.
		// rand.Prime должен возвращать простые числа с установленным старшим битом,
		// поэтому на практике повторных попыток не будет.
		p, err := rand.Prime(rand.Reader, bitLen/2)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(rand.Reader, bitLen/2)
		if err != nil {
			return nil, nil, err
		}

		// n = pq
		n := new(big.Int).Set(p)
		n.Mul(n, q)

		if n.BitLen() != bitLen {
			continue
		}

		// fi = (p-1)(q-1)
		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))
		fi := new(big.Int).Set(p)
		fi.Mul(fi, q)

		// e в данном случае прописывается в соответствии с рекомендациями PKCS#1 (RFC 2313) (e = 65537),
		// но может быть другим
		e := big.NewInt(65537)

		// Вычисляем d как мультипликативного обратного по модулю e:
		// de = 1 (mod fi)
		// Если gcd(e, fi) = 1, то e гарантированно будет иметь уникальную инверсию,
		// но поскольку p-1 или q-1 теоретически могут иметь e в качестве множителя,
		// время от времени это может давать сбой (вероятно, это будет чрезвычайно редко).
		d := new(big.Int).ModInverse(e, fi)
		if d == nil {
			continue
		}

		pub := &keys.PublicKey{N: n, E: e}
		priv := &keys.PrivateKey{N: n, D: d}
		fmt.Println("fi", fi.BitLen())
		fmt.Println()
		fmt.Println("q:", q.BitLen())
		fmt.Println()
		return pub, priv, nil
	}
}

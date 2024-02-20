package keys

import "math/big"

// PublicKey — это публичная часть пары RSA-ключей.
type PublicKey struct {
	N *big.Int
	E *big.Int
}

// PrivateKey — это секретная часть пары RSA-ключей.
// Согласно RFC 2313 мы могли бы включить сюда простые множители N и другие данные,
// чтобы ускорить расшифровку, но N и D достаточно для расшифровки сообщений.
type PrivateKey struct {
	N *big.Int
	D *big.Int
}

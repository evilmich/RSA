package main

import (
	"RSA-alg/internal/lib/decrypter"
	"RSA-alg/internal/lib/encrypter"
	"RSA-alg/internal/lib/keys/generator"
	"bufio"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("ВВЕДИТЕ СООБЩЕНИЕ:")
	str, err := reader.ReadBytes('\n')
	if err != nil {
		panic("Введено некорректное сообщение!!!")
	}
	fmt.Println()

	key1, key2, err := generator.GenerateKeys(2048)
	if err != nil {
		fmt.Println("Ошибка: ", err)
		return
	}

	enc, err := encrypter.EncryptRSA(key1, str)
	if err != nil {
		fmt.Println("Ошибка: ", err)
		return
	}
	fmt.Println("ЗАШИФРОВАННОЕ СООБЩЕНИЕ:")
	fmt.Println(" - Байты:")
	fmt.Println(enc)
	fmt.Println(" - Текст:")
	fmt.Println(string(enc))
	fmt.Println()

	dec, err := decrypter.DecryptRSA(key2, enc)
	if err != nil {
		fmt.Println("Ошибка: ", err)
		return
	}
	fmt.Println("РАСШИФРОВАННОЕ СООБЩЕНИЕ:")
	fmt.Println(string(dec))
}

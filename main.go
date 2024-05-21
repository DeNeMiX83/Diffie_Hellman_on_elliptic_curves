package main

import (
	"Diffie_Hellman_on_elliptic_curves/elliptic_curves"
	"fmt"
)

func main() {
	curve, err := elliptic_curves.NewEllipticCurve("prime256v1")
	if err != nil {
		fmt.Printf("Ошибка при создание элептической кривой ", err)
	}

	gp := curve.GetGP()
	privateKey, err := elliptic_curves.GenerateRandomNumber()
	if err != nil {
		fmt.Printf("Ошибка при создании простого числа")
	}
	publicKey := curve.GetPublickKey(privateKey)
}

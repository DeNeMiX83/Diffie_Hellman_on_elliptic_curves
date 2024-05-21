package main

import (
	"Diffie_Hellman_on_elliptic_curves/elliptic_curves"
	"Diffie_Hellman_on_elliptic_curves/tcp"
	"encoding/json"
	"fmt"
	"net"
)


func main() {
	curve, err := elliptic_curves.NewEllipticCurve("prime256v1")
	if err != nil {
		fmt.Printf("Ошибка при создание элептической кривой ", err)
	}
	serverConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Ошибка при подключении:", err)
	}
	serverTCPServer, _ := tcp.NewTCPHost(serverConn)
	defer serverConn.Close()

	privateKey, err := elliptic_curves.GenerateRandomNumber()
	if err != nil {
		fmt.Printf("Ошибка при создании простого числа")
	}
	publicKey := curve.GetPublickKey(privateKey)

	serializedKey, err := json.Marshal(publicKey)
	if err != nil {
		fmt.Println("ошибка сериализации: %v", err)
	}
	fmt.Println("Отправка публичного ключа клиента...")
	err = serverTCPServer.Send(serializedKey)
	if err != nil {
		fmt.Errorf("Ошибка отправки публичного ключа и gp: %v", err)
	}

	serverPubKeyBytes, err := serverTCPServer.Read()
	if err != nil {
		fmt.Println("ошибка чтения публичного ключа: %v", err)
	}
	fmt.Println("Публичный ключ сервера получен.")
	var serverPubKey elliptic_curves.Point
	err = json.Unmarshal(serverPubKeyBytes, &serverPubKey)
	if err != nil {
		fmt.Println("ошибка десериализации публичного ключа: %v", err)
	}

	secretKey := curve.GetSecretKey(privateKey, &serverPubKey)
	fmt.Println("Вычисленный секретный ключ: ", secretKey.X)
}

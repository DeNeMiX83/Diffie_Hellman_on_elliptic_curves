package main

import (
	"Diffie_Hellman_on_elliptic_curves/elliptic_curves"
	"Diffie_Hellman_on_elliptic_curves/tcp"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
)

func main() {
	curve, err := elliptic_curves.NewEllipticCurve("prime256v1")
	if err != nil {
		fmt.Printf("Ошибка при создание элептической кривой ", err)
	}
	privateKey, err := elliptic_curves.GenerateRandomNumber()
	if err != nil {
		fmt.Printf("Ошибка при создании простого числа")
	}
	publicKey := curve.GetPublickKey(privateKey)

	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server is listening on port 8080")

	for {
		// Accept incoming connections
		conn, err := listener.Accept()
		clientTCPServer, _ := tcp.NewTCPHost(conn)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		// Handle client connection in a goroutine
		go handleClient(clientTCPServer, curve, privateKey, publicKey)
	}
}

func handleClient(
	clientTCPServer *tcp.TCPHost,
	curve *elliptic_curves.EllipticCurve,
	privateKey *big.Int,
	publicKey *elliptic_curves.Point,
) {
	defer clientTCPServer.Close()

	pubKeyBytes, err := clientTCPServer.Read()
	if err != nil {
		fmt.Println("ошибка чтения публичного ключа: %v", err)
	}
	fmt.Println("Публичный ключ клиента получен.")
	var pubKey elliptic_curves.Point
	err = json.Unmarshal(pubKeyBytes, &pubKey)
	if err != nil {
		fmt.Println("ошибка десериализации публичного ключа: %v", err)
	}

	serializedKey, err := json.Marshal(publicKey)
	fmt.Println("Отправка публичного ключа клиенту...")
	err = clientTCPServer.Send(serializedKey)
	if err != nil {
		fmt.Errorf("Ошибка отправки публичного ключа и gp: %v", err)
	}

	secretKey := curve.GetSecretKey(privateKey, &pubKey)
	fmt.Println("Вычисленный секретный ключ: ", secretKey.X)
}

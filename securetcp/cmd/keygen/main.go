package main

import (
	"fmt"
	"log"

	"github.com/LwyV-Labs/LwyV-Net/securetcp"
)

func main() {
	kp, err := securetcp.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("PrivateKeyB64=", kp.PrivateKeyB64)
	fmt.Println("PublicKeyB64 =", kp.PublicKeyB64)
}

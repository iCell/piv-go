package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/ericchiang/piv-go/piv"
)

func generatePub(yk *piv.YubiKey) *ecdsa.PublicKey {
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyNever,
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication, key)
	if err != nil {
		log.Fatalln(err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		panic("convert ecdsa error")
	}

	return ecdsaPub
}

func exportPub(pub *ecdsa.PublicKey) {
	publicKey, _ := x509.MarshalPKIXPublicKey(pub)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	}

	pemFile, err := os.Create("./public.pem")
	defer pemFile.Close()
	if err != nil {
		panic(err)
	}

	err = pem.Encode(pemFile, &publicKeyBlock)
	if err != nil {
		panic(err)
	}
}

func importPub() *ecdsa.PublicKey {
	file, err := os.Open("./public.pem")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	pemfileinfo, _ := file.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))

	pub2, _ := x509.ParsePKIXPublicKey(data.Bytes)
	ecdsaPub, ok := pub2.(*ecdsa.PublicKey)
	if !ok {
		panic("convert ecdsa2 error")
	}

	return ecdsaPub
}

func main() {
	cards, err := piv.Cards()
	if err != nil {
		log.Fatal(err)
	}

	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yk, err = piv.Open(card)
			if err != nil {
				log.Fatalln(err)
			}
			break
		}
	}

	if yk == nil {
		panic("yubi key is nil")
	}

	// pub := generatePub(yk)
	// exportPub(pub)
	pub := importPub()

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	priv, err := yk.PrivateKey(piv.SlotAuthentication, pub, auth)
	if err != nil {
		panic(err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		panic("private key doesn't implement crypto.Signer")
	}

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	var ecdsaSignature struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &ecdsaSignature); err != nil {
		panic(err)
	}
	if !ecdsa.Verify(pub, hash, ecdsaSignature.R, ecdsaSignature.S) {
		panic("signature validation failed")
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}

package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type Block struct {
	Index        int
	Timestamp    string
	Message      string
	Decrypted    string
	Hash         string
	PreviousHash string
	Signature    string
}

type Rotor struct {
	Mapping  [26]int
	Position int
	Step     int
}

type EnigmaMachine struct {
	Rotors []*Rotor
}

func NewRotor(mapping [26]int, position int, step int) *Rotor {
	return &Rotor{Mapping: mapping, Position: position, Step: step}
}

func NewEnigmaMachine(rotors []*Rotor) *EnigmaMachine {
	return &EnigmaMachine{Rotors: rotors}
}

func (em *EnigmaMachine) RotateRotors() {
	for _, rotor := range em.Rotors {
		rotor.Position = (rotor.Position + rotor.Step) % 26
	}
}

func caesarCipher(text string, shift int) string {
	encoded := ""
	for _, char := range text {
		if char >= 'A' && char <= 'Z' {
			encoded += string((char-'A'+rune(shift))%26 + 'A')
		} else {
			encoded += string(char)
		}
	}
	return encoded
}

func (em *EnigmaMachine) Encrypt(message string, shift int) string {
	message = caesarCipher(message, shift)

	var encryptedMessage []rune
	for _, c := range message {
		if 'A' <= c && c <= 'Z' {
			encryptedChar := c
			for i := range em.Rotors {
				encryptedChar = rune('A' + em.Rotors[i].Mapping[(int(encryptedChar-'A')+em.Rotors[i].Position)%26])
			}
			encryptedMessage = append(encryptedMessage, encryptedChar)
			em.RotateRotors()
		} else if 'a' <= c && c <= 'z' {
			encryptedChar := c
			for i := range em.Rotors {
				encryptedChar = rune('a' + em.Rotors[i].Mapping[(int(encryptedChar-'a')+em.Rotors[i].Position)%26])
			}
			encryptedMessage = append(encryptedMessage, encryptedChar)
			em.RotateRotors()
		} else {
			encryptedMessage = append(encryptedMessage, c)
		}
	}
	return string(encryptedMessage)
}

func (em *EnigmaMachine) Decrypt(message string) string {
	var decryptedMessage []rune
	for _, c := range message {
		if 'A' <= c && c <= 'Z' {
			decryptedChar := c
			for i := len(em.Rotors) - 1; i >= 0; i-- {
				decryptedChar = rune('A' + (int(decryptedChar-'A')-em.Rotors[i].Position+26)%26)
			}
			decryptedMessage = append(decryptedMessage, decryptedChar)
			em.RotateRotors()
		} else if 'a' <= c && c <= 'z' {
			decryptedChar := c
			for i := len(em.Rotors) - 1; i >= 0; i-- {
				decryptedChar = rune('a' + (int(decryptedChar-'a')-em.Rotors[i].Position+26)%26)
			}
			decryptedMessage = append(decryptedMessage, decryptedChar)
			em.RotateRotors()
		} else {
			decryptedMessage = append(decryptedMessage, c)
		}
	}
	return string(decryptedMessage)
}

func calculateHash(block Block) string {
	record := string(block.Index) + block.Timestamp + block.Message + block.PreviousHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func signBlock(block Block, privkey *rsa.PrivateKey) string {
	h := sha256.New()
	h.Write([]byte(block.Hash))
	hashed := h.Sum(nil)

	signature, _ := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hashed)

	return hex.EncodeToString(signature)
}

func verifyBlock(block Block, pubkey *rsa.PublicKey) bool {
	signature, _ := hex.DecodeString(block.Signature)

	h := sha256.New()
	h.Write([]byte(block.Hash))
	hashed := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed, signature)

	return err == nil
}

func createBlock(oldBlock Block, message string, em *EnigmaMachine, privkey *rsa.PrivateKey) Block {
	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Message = em.Encrypt(message, 7) // Added the shift value of 7 here
	newBlock.PreviousHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)
	newBlock.Signature = signBlock(newBlock, privkey)

	return newBlock
}

func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privkey, &privkey.PublicKey
}

func handleConnection(conn net.Conn, blockchain *[]Block, em *EnigmaMachine, privkey *rsa.PrivateKey, pubkey *rsa.PublicKey) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	message, _ := reader.ReadString('\n')
	message = strings.TrimSpace(message)

	if message == "get" {
		for _, block := range *blockchain {
			conn.Write([]byte(fmt.Sprintf("Index: %d\n", block.Index)))
			conn.Write([]byte(fmt.Sprintf("Timestamp: %s\n", block.Timestamp)))
			conn.Write([]byte(fmt.Sprintf("Original Message: %s\n", block.Message)))              // Original message
			conn.Write([]byte(fmt.Sprintf("Decrypted Message: %s\n", em.Decrypt(block.Message)))) // Decrypted message
			conn.Write([]byte(fmt.Sprintf("Hash: %s\n", block.Hash)))
			conn.Write([]byte(fmt.Sprintf("PreviousHash: %s\n", block.PreviousHash)))
			conn.Write([]byte(fmt.Sprintf("Signature: %s\n", block.Signature)))
			conn.Write([]byte(fmt.Sprintf("Verified: %v\n", verifyBlock(block, pubkey))))
			conn.Write([]byte("\n"))
		}
	} else {
		newBlock := createBlock((*blockchain)[len(*blockchain)-1], message, em, privkey)

		// Update the newBlock with additional fields
		newBlock.Decrypted = em.Decrypt(message)
		newBlock.Index = len(*blockchain)
		newBlock.Timestamp = time.Now().String()
		newBlock.PreviousHash = (*blockchain)[len(*blockchain)-1].Hash

		*blockchain = append(*blockchain, newBlock)
		conn.Write([]byte("Block added\n"))
	}
}

func main() {
	blockchain := make([]Block, 1)
	blockchain[0] = Block{
		Index:        0,
		Timestamp:    time.Now().String(),
		Message:      "",
		Decrypted:    "",
		Hash:         "",
		PreviousHash: "",
		Signature:    "",
	}

	privkey, pubkey := generateKeys()

	rotor1 := NewRotor([26]int{4, 10, 12, 5, 11, 6, 3, 16, 21, 25, 13, 19, 14, 22, 24, 7, 23, 20, 18, 15, 0, 8, 1, 17, 2, 9}, 0, 1)
	rotor2 := NewRotor([26]int{0, 9, 3, 10, 18, 8, 17, 20, 23, 1, 11, 7, 22, 19, 12, 2, 16, 6, 25, 13, 15, 24, 5, 21, 14, 4}, 0, 2)
	rotor3 := NewRotor([26]int{1, 3, 5, 7, 9, 11, 2, 15, 17, 19, 23, 21, 25, 13, 24, 4, 8, 22, 6, 0, 10, 12, 20, 18, 16, 14}, 0, 3)

	em := NewEnigmaMachine([]*Rotor{rotor1, rotor2, rotor3})

	server, _ := net.Listen("tcp", ":8080")
	defer server.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, block := range blockchain {
			fmt.Fprintf(w, "Index: %d<br>", block.Index)
			fmt.Fprintf(w, "Timestamp: %s<br>", block.Timestamp)
			fmt.Fprintf(w, "Original Message: %s<br>", block.Message)    // Display original message
			fmt.Fprintf(w, "Decrypted Message: %s<br>", block.Decrypted) // Decrypted message
			fmt.Fprintf(w, "Hash: %s<br>", block.Hash)
			fmt.Fprintf(w, "PreviousHash: %s<br>", block.PreviousHash)
			fmt.Fprintf(w, "Signature: %s<br>", block.Signature)
			fmt.Fprintf(w, "Verified: %v<br>", verifyBlock(block, pubkey))
			fmt.Fprintf(w, "<br>")
		}
	})

	go http.ListenAndServe(":8081", nil)

	for {
		conn, _ := server.Accept()
		go handleConnection(conn, &blockchain, em, privkey, pubkey)
	}
}

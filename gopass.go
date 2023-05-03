package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Pwd struct {
	Website  string
	Username string
	Password string
}

var Reset = "\033[0m"
var Red = "\033[31m"
var Yellow = "\033[33m"
var Green = "\033[32m"

func WriteJSON(path string) {
	reader := bufio.NewReader(os.Stdin)

	if runtime.GOOS == "windows" {
		Reset = ""
		Red = ""
		Yellow = ""
		Green = ""
	}

	fmt.Print(Green + "\nEnter the website: " + Reset)
	website, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}

	website = strings.TrimSpace(website)

	fmt.Print(Green + "\nEnter the username: " + Reset)
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}
	username = strings.TrimSpace(username)

	fmt.Print(Green + "\nEnter the password: " + Reset)
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}
	password = strings.TrimSpace(password)

	pw := Pwd{
		Website:  website,
		Username: username,
		Password: password,
	}

	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Println(Red+"\nError reading the file:"+Reset, err)
		return
	}

	var pwd []Pwd
	if len(data) > 0 {
		err = json.Unmarshal(data, &pwd)
		if err != nil {
			fmt.Println(Red+"\nError unmarshaling the JSON data:"+Reset, err)
			return
		}
	}

	pwd = append(pwd, pw)

	jsonData, err := json.MarshalIndent(pwd, "", "  ")
	if err != nil {
		fmt.Println(Red+"\nError marshaling the notes:"+Reset, err)
		return
	}

	err = os.WriteFile(path, jsonData, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(Yellow+"\nWebsite: %s \nUsername: %s \nPassword: %s\n"+Reset, pw.Website, pw.Username, pw.Password)
}

func Encrypt(aeskey string, filename string) {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}

	key := []byte(aeskey)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext, err = Pkcs7Pad(plaintext, block.BlockSize())
	if err != nil {
		panic(err.Error())
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	f, err := os.Create(filename)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func Decrypt(aesKey string, inputFile string) {
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		panic(err.Error())
	}

	key := []byte(aesKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(ciphertext, ciphertext)
	ciphertext, _ = Pkcs7Unpad(ciphertext, aes.BlockSize)
	f, err := os.Create(inputFile)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

var (
	ErrInvalidBlockSize    = errors.New(Red + "\ninvalid blocksize" + Reset)
	ErrInvalidPKCS7Data    = errors.New(Red + "\ninvalid PKCS7 data (empty or not padded)" + Reset)
	ErrInvalidPKCS7Padding = errors.New(Red + "\ninvalid padding on input" + Reset)
)

func Pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func Pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func RandomBytes(num int) string {
	b := make([]byte, num)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s := fmt.Sprintf("%X", b)
	return s
}

func CreateFile(path string) {
	_, err := os.Stat(path)
	if err != nil {
		newFile, err := os.Create(path)
		fmt.Printf(Yellow + "\nFile does not exist, creating the file now.... \n" + Reset)
		if err != nil {
			fmt.Println(err)
		}
		log.Printf(Green+"%s has been created"+Reset, path)
		newFile.Close()
	}
}

func DeleteFile(path string) {
	err := os.Remove(path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(Red+"\n%s has been removed\n"+Reset, path)
}

func main() {
	var key string
	var input string
	var path string
	random := RandomBytes(16) // Generate a random key
	fmt.Println(Green + "\nWelcome to the password manager, what json or txt file do you have or would like to create?\n" + Reset)
	fmt.Scanln(&path)
	CreateFile(path)
	for {
		fmt.Println(Yellow + "\n1: Add a username and password 2: Encrypt your file 3: Decrypt your password 4: Delete file 5: Exit\n" + Reset)
		fmt.Println(Yellow + "Enter Your option: \n" + Reset)
		fmt.Scanln(&input)

		numinput, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf(Red+"\nSomething went wrong: %s\n"+Reset, err)
		}

		if numinput == 1 {
			WriteJSON(path)
		} else if numinput == 2 {
			if len(random) != 32 {
				fmt.Println(Red + "\nError: The key isn't exactly 32 characters long\n" + Reset)
				continue
			}
			Encrypt(random, path)
			fmt.Printf(Red+"\nKeep your key in a secure place to decrypt. Your password is: %s\n"+Reset, random)
		} else if numinput == 3 {
			fmt.Println(Green + "\nWhat is your randomly generated 32 key password?\n" + Reset)
			fmt.Scanln(&key)
			if len(key) != 32 {
				fmt.Println(Red + "\nError: The key must be exactly 32 characters long\n" + Reset)
				continue
			}
			Decrypt(key, path)
		} else if numinput == 4 {
			DeleteFile(path)
			fmt.Println(Yellow + "\nThank you for using the password manager, if you would like to use another file, please reset the program!\n" + Reset)
			break
		} else if numinput == 5 {
			fmt.Println(Yellow + "\nThank you for using the password manager, exiting...\n" + Reset)
			break
		} else {
			fmt.Println(Red + "\nInvalid choice, please choice one of the given options\n" + Reset)
			continue
		}
	}
}

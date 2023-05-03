package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "basic_padding",
			input:     []byte("test"),
			blockSize: 8,
			expected:  []byte("test\x04\x04\x04\x04"),
		},
		{
			name:      "no_padding_needed",
			input:     []byte("12345678"),
			blockSize: 8,
			expected:  []byte("12345678\x08\x08\x08\x08\x08\x08\x08\x08"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Pkcs7Pad(tc.input, tc.blockSize)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}

	t.Run("invalid_block_size", func(t *testing.T) {
		input := []byte("test")
		blockSize := 0
		_, err := Pkcs7Pad(input, blockSize)
		if err == nil {
			t.Errorf("Expected an error, but got nil")
		}
	})
}

func TestPkcs7Unpad(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
		expected  []byte
	}{
		{
			name:      "valid_unpadding",
			input:     []byte("test\x04\x04\x04\x04"),
			blockSize: 8,
			expected:  []byte("test"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Pkcs7Unpad(tc.input, tc.blockSize)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}

	t.Run("invalid_block_size", func(t *testing.T) {
		input := []byte("test\x04\x04\x04\x04")
		blockSize := 0
		_, err := Pkcs7Unpad(input, blockSize)
		if err == nil {
			t.Errorf("Expected an error, but got nil")
		}
	})

	t.Run("invalid_padding", func(t *testing.T) {
		input := []byte("test\x04\x04\x03\x04")
		blockSize := 8
		_, err := Pkcs7Unpad(input, blockSize)
		if err == nil {
			t.Errorf("Expected an error, but got nil")
		}
	})
}

func TestRandomBytes(t *testing.T) {
	randomBytes := RandomBytes(16)

	if len(randomBytes) != 32 {
		t.Errorf("Expected a string of length 32, but got %d", len(randomBytes))
	}
}

func TestCreateFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.json")

	CreateFile(testFile)

	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("Expected the file to be created, but it was not: %v", err)
	}
}

func TestDeleteFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.json")

	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}
	f.Close()

	DeleteFile(testFile)

	if _, err := os.Stat(testFile); err == nil {
		t.Errorf("Expected the file to be deleted, but it still exists")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.json")
	testContent := `{"website": "example.com", "username": "user", "password": "pass"}`

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Error writing test content to file: %v", err)
	}

	key := RandomBytes(16)
	Encrypt(key, testFile)

	encryptedContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Error reading encrypted content from file: %v", err)
	}

	if string(encryptedContent) == testContent {
		t.Errorf("Expected the content to be encrypted, but it is not")
	}

	Decrypt(key, testFile)

	decryptedContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Error reading decrypted content from file: %v", err)
	}

	if string(decryptedContent) != testContent {
		t.Errorf("Expected the content to be decrypted, but it is not")
	}
}

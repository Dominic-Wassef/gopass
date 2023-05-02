package main

import (
	"bytes"
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

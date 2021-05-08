/*
 * MIT License
 *
 * Copyright (C) 2021 Crimson Technologies LLC. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package aesccm

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

type ccm struct {
	blockCipher cipher.Block
	mac         *cbcMac
	nonceSize   int
	tagSize     int
}

var (
	// ErrInvalidBlockSize indicates that the cipher blockCipher passed in NewCCMWithNonceAndTagSizes
	// is not CbcMacBlockSize.
	ErrInvalidBlockSize = errors.New("cipher: CCM mode requires 128-bit block")

	// ErrInvalidNonceSize indicates that the nonce size is invalid.
	ErrInvalidNonceSize = errors.New("cipher: invalid nonce size for CCM mode")

	// ErrInvalidTagSize indicates that the tag size is invalid.
	ErrInvalidTagSize = errors.New("cipher: invalid tag size for CCM mode")

	// ErrMaxPayloadSizeReached indicates that the max payload size has been reached.
	ErrMaxPayloadSizeReached = errors.New("cipher: max payload size reached for CCM mode")

	// ErrAuthenticationFailed indicates that verifying the integrity of the decrypted message failed.
	ErrAuthenticationFailed = errors.New("cipher: authentication failed for CCM mode")
)

// getTag reuses a counter block for making the B0 block as per A.2 and A.3.
func (c *ccm) getTag(ctr, data, plaintext []byte) []byte {
	c.mac.Reset()

	cpy := ctr                                              // B0
	cpy[0] |= byte(((c.tagSize - 2) / 2) << 3)              // [(t-2)/2]3
	putUVarInt(cpy[1+c.nonceSize:], uint64(len(plaintext))) // Q

	if len(data) > 0 {
		cpy[0] |= 1 << 6 // Adata

		_, _ = c.mac.Write(cpy)

		if len(data) < (1<<15 - 1<<7) {
			putUVarInt(cpy[:2], uint64(len(data)))

			_, _ = c.mac.Write(cpy[:2])
		} else if len(data) <= 1<<31-1 {
			cpy[0], cpy[1] = 0xff, 0xfe
			putUVarInt(cpy[2:6], uint64(len(data)))

			_, _ = c.mac.Write(cpy[:6])
		} else {
			cpy[0], cpy[1] = 0xff, 0xff
			putUVarInt(cpy[2:10], uint64(len(data)))

			_, _ = c.mac.Write(cpy[:10])
		}

		_, _ = c.mac.Write(data)
		c.mac.PadZero()
	} else {
		_, _ = c.mac.Write(cpy)
	}

	_, _ = c.mac.Write(plaintext)
	c.mac.PadZero()

	return c.mac.Sum(nil)
}

func (c *ccm) NonceSize() int {
	return c.nonceSize
}

func (c *ccm) Overhead() int {
	return c.tagSize
}

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.NonceSize() {
		panic("cipher: incorrect nonce length given to CCM")
	}

	// can't return an error, return nil instead
	if maxUnsignedVarInt(15-c.nonceSize) < uint64(len(plaintext)) {
		return nil
	}

	ret, ciphertext := sliceForAppend(dst, len(plaintext)+c.mac.Size())

	// format counter blocks as defined in A.3
	counterBlock := make([]byte, 16)             // Ctr0
	counterBlock[0] = byte(15 - c.nonceSize - 1) // [q-1]3
	copy(counterBlock[1:], nonce)                // N

	s0 := ciphertext[len(plaintext):]
	c.blockCipher.Encrypt(s0, counterBlock)

	counterBlock[15] = 1 // Ctr1

	ctr := cipher.NewCTR(c.blockCipher, counterBlock)
	ctr.XORKeyStream(ciphertext, plaintext)

	T := c.getTag(counterBlock, additionalData, plaintext)
	xorBytes(s0, s0, T) // T ^ S0

	return ret[:len(plaintext)+c.tagSize]
}

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, ErrInvalidNonceSize
	}

	if len(ciphertext) <= c.tagSize {
		return nil, ErrInvalidTagSize
	}

	if maxUnsignedVarInt(15-c.nonceSize) < uint64(len(ciphertext)-c.tagSize) {
		return nil, ErrMaxPayloadSizeReached
	}

	ret, plaintext := sliceForAppend(dst, len(ciphertext)-c.tagSize)

	// format counter blocks as defined in A.3
	counterBlock := make([]byte, 16)             // Ctr0
	counterBlock[0] = byte(15 - c.nonceSize - 1) // [q-1]3
	copy(counterBlock[1:], nonce)                // N

	s0 := make([]byte, 16) // S0
	c.blockCipher.Encrypt(s0, counterBlock)

	counterBlock[15] = 1 // Ctr1

	ctr := cipher.NewCTR(c.blockCipher, counterBlock)
	ctr.XORKeyStream(plaintext, ciphertext[:len(plaintext)])

	T := c.getTag(counterBlock, additionalData, plaintext)
	xorBytes(T, T, s0)

	if !bytes.Equal(T[:c.tagSize], ciphertext[len(plaintext):]) {
		return nil, ErrAuthenticationFailed
	}

	return ret, nil
}

// NewCCM creates a new AES-CCM cipher given the cipher block, nonce size and tag size.
func NewCCM(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if block.BlockSize() != CbcMacBlockSize {
		return nil, ErrInvalidBlockSize
	}

	if !(7 <= nonceSize && nonceSize <= 13) {
		return nil, ErrInvalidNonceSize
	}

	if !(4 <= tagSize && tagSize <= 16 && tagSize&1 == 0) {
		return nil, ErrInvalidTagSize
	}

	return &ccm{
		blockCipher: block,
		mac:         newCBCMACFromBlock(block),
		nonceSize:   nonceSize,
		tagSize:     tagSize,
	}, nil
}

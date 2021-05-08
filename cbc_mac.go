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

import "crypto/cipher"

// cbcMac is an implementation of CBC-MAC.
type cbcMac struct {
	ci    []byte
	p     int
	block cipher.Block
}

func (mac *cbcMac) Write(p []byte) (n int, err error) {
	for _, c := range p {
		if mac.p >= len(mac.ci) {
			mac.block.Encrypt(mac.ci, mac.ci)
			mac.p = 0
		}

		mac.ci[mac.p] ^= c
		mac.p++
	}

	return len(p), nil
}

func (mac *cbcMac) Sum(b []byte) []byte {
	if mac.p != 0 {
		mac.block.Encrypt(mac.ci, mac.ci)
		mac.p = 0
	}

	return append(b, mac.ci...)
}

func (mac *cbcMac) Reset() {
	for i := range mac.ci {
		mac.ci[i] = 0
	}

	mac.p = 0
}

func (mac *cbcMac) Size() int {
	return len(mac.ci)
}

// CbcMacBlockSize is the block size of the CBC-MAC implementation.
const CbcMacBlockSize = 16

func (mac *cbcMac) BlockSize() int {
	return CbcMacBlockSize
}

// PadZero emulates zero byte padding.
func (mac *cbcMac) PadZero() {
	if mac.p != 0 {
		mac.block.Encrypt(mac.ci, mac.ci)
		mac.p = 0
	}
}

// newCBCMACFromBlock creates a new cbcMac from the specified cipher.Block.
func newCBCMACFromBlock(block cipher.Block) *cbcMac {
	return &cbcMac{
		ci:    make([]byte, block.BlockSize()),
		block: block,
	}
}

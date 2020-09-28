/**
 * Copyright (c) 2020, Cloudless Consulting Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

// To skip a test, either use 'xit' instead of 'it', or 'describe.skip' instead of 'describe'

const { assert } = require('chai')
const { numberToBase64, base64ToNumber } = require('../src/utils')

describe('utils', () => {
	describe('#numberToBase64', () => {
		it('01 - Should convert big numbers into base64', () => {
			const b64 = numberToBase64(65537)
			assert.equal(b64, 'AQAB', '01')
		})
	})
	describe('#base64ToNumber', () => {
		it('01 - Should convert base64 to big number', () => {
			const nbr = base64ToNumber('AQAB')
			assert.equal(nbr, 65537, '01')
		})
	})
})
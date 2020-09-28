/**
 * Copyright (c) 2020, Cloudless Consulting Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

// To skip a test, either use 'xit' instead of 'it', or 'describe.skip' instead of 'describe'

const { assert } = require('chai')
const { Keypair, Key } = require('../src')

class WrapperError extends Error {
	constructor(message, stack) {
		super(message)
		this.stack = stack
	}
}

const assertNoErrors = (errors, comment) => {
	try {
		assert.isNotOk(errors, comment)
	} catch(error) {
		const totalErrors = [error, ...errors]
		const stack = totalErrors.map(e => e.stack).join('\n')
		throw new WrapperError(error.message, stack)
	}
}

describe('Keypair', () => {
	describe('create', () => {
		it('01 - Should create a RSA pem and JWK keys.', async () => {
			const keypair = new Keypair({ cipher:'rsa' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')
			assert.isOk(pemKeys, '04')
			assert.isOk(pemKeys.private, '05')
			assert.isOk(pemKeys.public, '06')
			assert.isOk(jwkKeys.private, '07')
			assert.isOk(jwkKeys.public, '08')

		})
		it('02 - Should reconstruct the RSA public pem key from JWK formats.', async () => {
			const keypair = new Keypair({ cipher:'rsa' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')

			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')

			const key = new Key({ jwk:jwkKeys.public })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.public,'04')

		})
		it('03 - Should reconstruct the RSA private pem key from JWK formats.', async () => {
			const keypair = new Keypair({ cipher:'rsa' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')

			const key = new Key({ jwk:jwkKeys.private })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.private,'04')

		})
		it('04 - Should create a ECDSA pem and JWK keys.', async () => {
			const keypair = new Keypair({ cipher:'ec' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')
			assert.isOk(pemKeys, '04')
			assert.isOk(pemKeys.private, '05')
			assert.isOk(pemKeys.public, '06')
			assert.isOk(jwkKeys.private, '07')
			assert.isOk(jwkKeys.public, '08')

		})
		it('05 - Should reconstruct the ECDSA public pem key from JWK formats.', async () => {
			const keypair = new Keypair({ cipher:'ec' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')

			const key = new Key({ jwk:jwkKeys.public })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.public,'04')

		})
		it('06 - Should reconstruct the ECDSA private pem key from JWK formats.', async () => {
			const keypair = new Keypair({ cipher:'ec' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')

			const key = new Key({ jwk:jwkKeys.private })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.private,'04')

		})
	})	
})





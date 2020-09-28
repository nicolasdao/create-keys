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
const jwktossh = require('jwk-to-ssh')
const sshtojwk = require('ssh-to-jwk')

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

const privateRsaSshKeygen = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAssS9Iyw8lPyjbmZE2q7veK1Sw/I1tY4n/OVBHcvL9Jl9vj/FuZYD
/2kb8kaiPzLExbeEiTLMmdpAHc2qWngYETl+1vUHRCaj0azBDULIwJsMlm3vVotnM1yKFZ
F2I71BXw8CpU96g94NtJ+heNa5hbBuLdqjW6DfYoh21+cbk9kK4bMF23LCmrIUmliQ9WJC
30J60vRCjZNcrbY+oZZ1xn4bm/rielMwMr0ywFP/Eb44JspXSAVAz1NeqvcvZBU5UJFIGo
iUHlnbGb83AkyY0cYxCMGWIXEzMyCyIBxT/r5O+lw2izKeJEKfRtR4HpMXPDLlEwsVH9Ae
rYtEFE+V0QAAA+Ad+MOYHfjDmAAAAAdzc2gtcnNhAAABAQCyxL0jLDyU/KNuZkTaru94rV
LD8jW1jif85UEdy8v0mX2+P8W5lgP/aRvyRqI/MsTFt4SJMsyZ2kAdzapaeBgROX7W9QdE
JqPRrMENQsjAmwyWbe9Wi2czXIoVkXYjvUFfDwKlT3qD3g20n6F41rmFsG4t2qNboN9iiH
bX5xuT2QrhswXbcsKashSaWJD1YkLfQnrS9EKNk1yttj6hlnXGfhub+uJ6UzAyvTLAU/8R
vjgmyldIBUDPU16q9y9kFTlQkUgaiJQeWdsZvzcCTJjRxjEIwZYhcTMzILIgHFP+vk76XD
aLMp4kQp9G1Hgekxc8MuUTCxUf0B6ti0QUT5XRAAAAAwEAAQAAAQEAl7LFgRxfyFneYaed
FClQgwopaqeVlhwsqLjuGde/mi/J+XBqXAMGH23VTjFMKu7s9Y62hCo8Xu5KbEADKEQywC
MXFFfXM6jKaPn81EDw1Ch+dQSTDdC74WTMtGK8arWFzKGTMC6Sm2YKIVU4k686vUyrInQf
HXkVNqrwlmPCDiG7uZ6igFKQhe9UHxpD/VfVqekd2tCKeJtKpWezR9S0GhRT8DI03XVpJe
ZGaUmftOKglrSCWEYzjor7Tg6SRqMQIeFBuNQPJvtsWEKbsCW+OZ7YrcK4x4772hgRq6yS
JPfFBpqAkepW3P1gwb+WDIJP0vkDiFAMLiq4B/F67OP8FQAAAIEAs9OzT6hsDO7dXpCTNx
IbSZo2KHzJD4XR3EtcWZ1u98iaBc3LujEWdkSvJ4EW0A4AOAJkycX9BegkZzJh/STR4b+/
KPgZ9UmUQfBLM4H5KYAjAl5NJiwTkt4CRqk4GXKRYhhNjeM1/0SsscLpw66ztFVTUrosVS
Z7YnGNv3XVBG0AAACBANe9fBt9nJzpfuHtp4GmE3kIRevOi1XfoS0M+XFYxN+u84sDF1Ps
uRFFvEkBiyP2R6q07ZIcHGqCWxNyvHFU7lGm+skxEtjOtUzOylVnD6AhfkgUbm4WrqflWK
8qwtjw/NXOGyArWHSIgHorK/CY95hY+d8fgoPye4jaE0M3qxlPAAAAgQDUIQN7oZYx8/KZ
tPiZLI3aUOLPKLpEXtqwoDmWhZho5fnobeJ/cTZryOAZiJOg7wyr1Ein9weS36LHts9Xum
snVIN7Se+D3WkmRluviJHuheFPw9UbphjtOmuhVYTx/71BvSqauGMBCwzANrEKrU8GbJDW
QXDNiwCQ5cTWLvxW3wAAACduaWNvbGFzZGFvQE5pY29sYXNzLU1hY0Jvb2stUHJvLTIubG
9jYWwBAg==
-----END OPENSSH PRIVATE KEY-----
`

const publicRsaSshKeygen = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyxL0jLDyU/KNuZkTaru94rVLD8jW1jif85UEdy8v0mX2+P8W5lgP/aRvyRqI/MsTFt4SJMsyZ2kAdzapaeBgROX7W9QdEJqPRrMENQsjAmwyWbe9Wi2czXIoVkXYjvUFfDwKlT3qD3g20n6F41rmFsG4t2qNboN9iiHbX5xuT2QrhswXbcsKashSaWJD1YkLfQnrS9EKNk1yttj6hlnXGfhub+uJ6UzAyvTLAU/8RvjgmyldIBUDPU16q9y9kFTlQkUgaiJQeWdsZvzcCTJjRxjEIwZYhcTMzILIgHFP+vk76XDaLMp4kQp9G1Hgekxc8MuUTCxUf0B6ti0QUT5XR nicolasdao@Nicolass-MacBook-Pro-2.local`

describe('Keypair', () => {
	describe('create', () => {
		it('01 - Should create a RSA pem, JWK and ssh keys.', async () => {
			const keypair = new Keypair({ cipher:'rsa' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			const [sshErrors, sshKeys] = await keypair.to('ssh')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')
			assertNoErrors(sshErrors, '03')
			assert.isOk(pemKeys, '04')
			assert.isOk(pemKeys.private, '05')
			assert.isOk(pemKeys.public, '06')
			assert.isOk(jwkKeys.private, '07')
			assert.isOk(jwkKeys.public, '08')
			assert.isOk(sshKeys.private, '09')
			assert.isOk(sshKeys.public, '10')

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
		it('04 - Should reconstruct the RSA public pem key from SSH formats.', async () => {
			const keypair = new Keypair({ cipher:'rsa' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [sshErrors, sshKeys] = await keypair.to('ssh')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(sshErrors, '02')

			const key = new Key({ ssh:sshKeys.public })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.public,'04')

		})
		it('05 - Should create a ECDSA pem, JWK and ssh keys.', async () => {
			const keypair = new Keypair({ cipher:'ec' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [jwkErrors, jwkKeys] = await keypair.to('jwk')
			const [sshErrors, sshKeys] = await keypair.to('ssh')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(jwkErrors, '02')
			assertNoErrors(sshErrors, '03')
			assert.isOk(pemKeys, '04')
			assert.isOk(pemKeys.private, '05')
			assert.isOk(pemKeys.public, '06')
			assert.isOk(jwkKeys.private, '07')
			assert.isOk(jwkKeys.public, '08')
			assert.isOk(sshKeys.private, '09')
			assert.isOk(sshKeys.public, '10')

		})
		it('06 - Should reconstruct the ECDSA public pem key from JWK formats.', async () => {
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
		it('07 - Should reconstruct the ECDSA private pem key from JWK formats.', async () => {
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
		it('08 - Should reconstruct the ECDSA public pem key from SSH formats.', async () => {
			const keypair = new Keypair({ cipher:'ec' })
			const [pemErrors, pemKeys] = await keypair.to('pem')
			const [sshErrors, sshKeys] = await keypair.to('ssh')
			
			assertNoErrors(pemErrors, '01')
			assertNoErrors(sshErrors, '02')

			const key = new Key({ ssh:sshKeys.public })
			const [pemKeyErrors, pemKey] = key.to('pem')

			assertNoErrors(pemKeyErrors, '03')
			assert.equal(pemKey, pemKeys.public,'04')

		})
	})	
})

describe('Key', () => {
	describe('to', () => {
		it('01 - Should convert private SSH key created with ssh-keygen to JWK', () => {
			const key = new Key({ ssh:privateRsaSshKeygen })
			const [errors, jwk] = key.to('jwk')

			assertNoErrors(errors, '01')
			assert.equal(jwk.kty, 'RSA', '02')
			assert.isOk(jwk.e, '03')
			assert.isOk(jwk.n, '04')
			assert.isOk(jwk.d, '05')
			assert.isOk(jwk.p, '06')
			assert.isOk(jwk.q, '07')
			assert.isOk(jwk.dmp1, '08')
			assert.isOk(jwk.dmq1, '09')
			assert.isOk(jwk.coeff, '10')
		})
		it('02 - Should convert private SSH key created with ssh-keygen to JWK', () => {
			const [, jwk] = new Key({ ssh:privateRsaSshKeygen }).to('jwk')
			const { jwk:j2 } = sshtojwk.parse({ pem:privateRsaSshKeygen })
			console.log(jwk)
			console.log(j2)
			// const pem = jwktossh.pack({ jwk })

			// assertNoErrors(errors, '01')
			// /console.log(pem)
		})
	})
})





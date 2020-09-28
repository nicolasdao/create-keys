const getPem = require('rsa-pem-from-mod-exp')
const { error: { catchErrors, wrapErrors } } = require('puffy')
// const { pem2jwk } = require('pem-jwk')
const NodeRSA = require('node-rsa')
const { numberToBase64, base64ToNumber, jwtBuffer, jwtB64 } = require('./utils')

/**
 * Create a PEM string from a public RSA modulus and exponent. 
 * 
 * @param  {String} input.modulus || input.n
 * @param  {String} input.exponent || input.e
 * 
 * @return {String} publicKey
 */
const jwkToPem = (input={}) => catchErrors(() => {
	const errorMsg = 'Failed to create public RSA key from modulus and exponent'
	const { modulus, n, exponent, e } = input
	const mod = modulus || n
	const exp = exponent || e
	if (!mod)
		throw new Error(`${errorMsg}. Missing required 'modulus|n'`)
	if (!exp)
		throw new Error(`${errorMsg}. Missing required 'exponent|e'`)

	const jwk = modulus && exponent ? { kty:'RSA', n:modulus, e:exponent } : input

	const isPrivate = jwk.d !== undefined
	
	if (isPrivate) {
		const jwkBuff = jwtBuffer(jwk)
		try {
			const key = new NodeRSA()
			key.importKey(jwkBuff, 'components')
			return key.exportKey('pkcs8-private-pem') + '\n'
		} catch(err) {
			throw wrapErrors(errorMsg, [err])
		}
	} else {
		const jwkBase64 = jwtB64(jwk)
		try {
			return getPem(jwkBase64.n, jwkBase64.e)
		} catch(err) {
			throw wrapErrors(errorMsg, [err])
		}
	}
})

const pemToJwk = (pemKey, isPrivate) => catchErrors(() => {
	const errorMsg = 'Failed to convert RSA key from PEM to JWK format'

	try {
		const rsaKey = new NodeRSA(pemKey)
		const jwt = rsaKey.exportKey(`components-${isPrivate ? 'private' : 'public'}-pem`)
		const core = {
			kty: 'RSA',
			e: jwt.e,
			n: jwt.n
		}
		if (isPrivate) 
			return jwtB64({
				...core,
				d: jwt.d,
				p: jwt.p,
				q: jwt.q,
				dmp1: jwt.dmp1,
				dmq1: jwt.dmq1,
				coeff: jwt.coeff
			})
		else
			return jwtB64(core)
	} catch(err) {
		throw wrapErrors(errorMsg, [err])
	}
})

module.exports = {
	jwkToPem,
	pemToJwk
}

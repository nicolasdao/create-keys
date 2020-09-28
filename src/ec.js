const ECKey = require('./ec-key')
const { error: { catchErrors, wrapErrors } } = require('puffy')

const pemToJwk = pem => catchErrors(() => {
	const errorMsg = 'Failed to convert ECDSA key from PEM to JWK format'

	try {
		const jwk = new ECKey(pem, 'pem')
		jwk.crv = jwk.curve
		delete jwk.curve
		return jwk
	} catch(err) {
		throw wrapErrors(errorMsg, [err])
	}
})

const jwkToPem = (jwk) => catchErrors(() => {
	const errorMsg = 'Failed to convert ECDSA key from JWK to PEM format'

	try {
		const key = new ECKey(jwk)
		return key.toString()
	} catch(err) {
		throw wrapErrors(errorMsg, [err])
	}
})

module.exports = {
	pemToJwk,
	jwkToPem
}
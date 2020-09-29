const crypto = require('crypto')
const { error:{ catchErrors, wrapErrors } } = require('puffy')
const rsaHelp = require('./rsa')
const ecHelp = require('./ec')
const { cleanJwk } = require('./utils')

const SUPPORTED_FORMATS = ['pem', 'jwk', 'ssh']

const generateKeyPair = (cipher, config) => new Promise(success => crypto.generateKeyPair(cipher, config, (err, publicKey, privateKey) => {
	const errors = err ? [err] : null
	const results = publicKey && privateKey ? { public:publicKey, private:privateKey } : null
	success([errors, results])
}))

const isPemKeyPrivate = (pemKey='', options={}) => {
	const { private:privateType, public:publicType } = options
	const isPrivate = privateType !== undefined ? privateType : publicType !== undefined ? !publicType : pemKey.indexOf('PRIVATE') >= 0
	return isPrivate
}

const jwkKeyToPem = (jwkKey={}) => jwkKey.crv ? ecHelp.jwkToPem(jwkKey) : rsaHelp.jwkToPem(jwkKey)

const rsaKeyPemToJwk = (pemKey='', options={}) => catchErrors(() => {
	const isPrivate = isPemKeyPrivate(pemKey, options)
	const errorMsg = `Failed to convert RSA ${isPrivate ? 'private' : 'public'} key from PEM to JWK format`

	const [errors, jwk] = rsaHelp.pemToJwk(pemKey, isPrivate)
	if (errors)
		throw wrapErrors(errorMsg, errors)
	return jwk
})

const ecKeyPemToJwk = (pemKey='', options={}) => catchErrors(() => {
	const isPrivate = isPemKeyPrivate(pemKey, options)
	const errorMsg = `Failed to convert ECDSA ${isPrivate ? 'private' : 'public'} key from PEM to JWK format`

	const [errors, jwk] = ecHelp.pemToJwk(pemKey)
	if (errors)
		throw wrapErrors(errorMsg, errors)
	return jwk
})

const pemKeyToJwk = (pemKey='', options={}) => catchErrors(() => {
	const isPrivate = isPemKeyPrivate(pemKey, options)
	const [rsaErrors, rsaJwk] = rsaKeyPemToJwk(pemKey,options)
	const [ecErrors, ecJwk] = ecKeyPemToJwk(pemKey,options)

	if (rsaErrors && ecErrors)
		throw new Error(`Failed to convert ${isPrivate ? 'private' : 'public'} key from PEM to JWK format. The PEM key cannot is not recognized as a valid RSA or ECDSA key.`)

	return cleanJwk(rsaErrors ? ecJwk : rsaJwk)
})

const rsaKeyPairPemToJwk = ({ private:privateKey, public:publicKey }) => catchErrors(() => {
	const errorMsg = 'Failed to convert RSA keypair from PEM to JWK'
	const [privateJwkErrors, privateJwk] = rsaKeyPemToJwk(privateKey, { private:true })
	const [publicJwkErrors, publicJwk] = rsaKeyPemToJwk(publicKey, { public:true })

	if (privateJwkErrors || publicJwkErrors)
		throw wrapErrors(errorMsg, privateJwkErrors || publicJwkErrors)

	return {
		private: privateJwk,
		public: publicJwk
	}
})


const ecKeyPairPemToJwk = ({ private:privateKey, public:publicKey }) => catchErrors(() => {
	const errorMsg = 'Failed to convert ECDSA keypair from PEM to JWK'
	const [privateJwkErrors, privateJwk] = ecKeyPemToJwk(privateKey)
	const [publicJwkErrors, publicJwk] = ecKeyPemToJwk(publicKey)

	if (privateJwkErrors || publicJwkErrors)
		throw wrapErrors(errorMsg, privateJwkErrors || publicJwkErrors)

	return {
		private: privateJwk,
		public: publicJwk
	}
})

const keyPairPemToJwk = cipher => cipher == 'rsa' ? rsaKeyPairPemToJwk : ecKeyPairPemToJwk

/**
 * Creates a new asymmetric Keypair instance. 
 * 
 * @param  {String}		passphrase			
 * @param  {String}		cipher					Valid values: 'rsa' (default), 'dsa', 'ec', 'ed25519', 'ed448', 'x25519', 'x448', or 'dh'	
 * @param  {Number}		length					Default 2048
 * @param  {String}		curve					Default 'prime256v1'. Only used for cipher 'ec'.
 * 
 * @return {Keypair}	keypair	
 */
function Keypair(config) {
	const { passphrase, cipher='rsa', length=2048, curve='prime256v1' } = config
	const isRSA = cipher == 'rsa'

	const encryptionConfig = passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}
	const ecConfig = cipher == 'ec' ? { namedCurve:curve } : {}
	const rsaConfig = isRSA ? { modulusLength:length } : {}
	const publicKeyType = isRSA ? 'pkcs1' : 'spki'

	const errorMsg = 'Failed to create new Keypair instance'

	if (cipher != 'rsa' && cipher != 'ec')
		throw new Error(`${errorMsg}. Cipher '${cipher}' is not supported. Supported ciphers are: rsa and ec.`)

	const keyPairConfig = {
		...rsaConfig,
		...ecConfig,
		publicKeyEncoding: {
			type: publicKeyType,
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem',
			...encryptionConfig
		}
	}

	const pemAsyncResult = generateKeyPair(cipher, keyPairConfig)

	this.to = (type='pem') => catchErrors((async () => {
		const errorMsg = `Failed to create asymmetric ${cipher} keys in ${type} format`
		if (SUPPORTED_FORMATS.indexOf(type) < 0)
			throw new Error(`File format '${type}' is not supported`)

		const [pemErrors, pemResult] = await pemAsyncResult
		if (pemErrors)
			throw wrapErrors(errorMsg, pemErrors)
		if (type == 'pem')
			return pemResult
		else {
			const [errors, result] = keyPairPemToJwk(cipher)(pemResult)
			if (errors)
				throw wrapErrors(errorMsg, errors)
			return result
		}
	})())

	return this
}


/**
 * Creates a new asymmetric Key instance. 
 * 
 * @param {Object}	config.jwk			Key in its JWK form.
 * @param {String}	config.pem			Key in its PEM form.
 */
function Key(config={}) {
	const errorMsg = 'Failed to create new Key instance'
	const { jwk, pem } = config
	if (jwk === undefined && pem === undefined)
		throw new Error(`${errorMsg}. Missing required key. At least one of those three properties is required: jwk, pem or ssh`)

	const keyFormat = jwk ? 'jwk' : pem ? 'pem' : 'ssh'

	this.to = (type='pem') => catchErrors(() => {
		const errorMsg = `Failed to convert asymmetric key in ${type} format`
		if (SUPPORTED_FORMATS.indexOf(type) < 0)
			throw new Error(`File format '${type}' is not supported`)

		if (keyFormat == 'pem') {
			if (type == 'pem')
				return pem
			else { // jwk
				const [errors, jwkFormat] = pemKeyToJwk(pem)
				if (errors)
					throw wrapErrors(errorMsg, errors)
				return jwkFormat
			}
		} else { // jwk
			if (type == 'pem') {
				const [errors, pemFormat] = jwkKeyToPem(jwk)
				if (errors)
					throw wrapErrors(errorMsg, errors)
				return pemFormat
			} else  // jwk
				return jwk
		}
	})

	return this
}


module.exports = {
	Keypair,
	Key
}







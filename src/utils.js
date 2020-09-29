const crypto = require('crypto')
require('colors')
const { fetch, error:{ catchErrors, wrapErrors } } = require('puffy')
const { getUniqueFileName, write } = require('./file')


// Only the following curves support JWK convertion from pem thanks the the 'ec-key' package.
const EC_FULLY_SUPPORTED_CURVES = ['prime256v1', 'secp384r1']
// Full list: ['rsa', 'dsa', 'ec', 'ed25519', 'ed448', 'x25519', 'x448', 'dh']
// At this stage of this project, we only support a subset of those ciphers.
const CIPHERS = ['rsa', 'ec']
const RSA_KEY_LENGTH = [512, 1024, 2048, 4096]

const doesCurveSupportJwkFormat = curve => EC_FULLY_SUPPORTED_CURVES.indexOf(curve) >= 0

const getEcCurves = () => {
	const allCurves = crypto.getCurves().filter(c => !doesCurveSupportJwkFormat(c)).map(c => ({ name:c, value:c }))
	return [
		...EC_FULLY_SUPPORTED_CURVES.map(c => ({ name:`${c} (supports JWK and SSH format)`, value:c })),
		...allCurves
	]
}

const getDefaultChoice = (choices=[], value) => choices
	.map(c => c && c.value ? c.value : c)
	.indexOf(value)

const printErrors = (errors=[]) => {
	errors.forEach(e => {
		if (e.stack) {
			const [firstLine, ...lines] = e.stack.split('\n')
			console.log(firstLine.red.bold)
			lines.forEach(l => console.log(l.red))
		} else
			console.log(e.message.red.bold)
	})
}

/**
 * Re-asks the prompt question when there is a missing required field. 
 * 
 * @param  {Function}	prompt				(:Void): Prompt
 * @param  {[String]}	requiredFields
 * 
 * @return {Object}			
 */
const requiredPrompt = async (prompt, ...requiredFields) => {
	const answers = await prompt()
	const missingRequiredField = requiredFields.filter(field => {
		const val = answers[field]
		if (!val)
			return true
		else if (Array.isArray(val) && !val.length)
			return true 
		else
			return false
	})[0]

	if (missingRequiredField) {
		console.log(`  ${missingRequiredField} is required`.bold.red)
		return await requiredPrompt(prompt, ...requiredFields)
	} else
		return answers
}

const numberToBase64 = nbr => {
	let hex = nbr.toString(16)
	if (hex.length % 2) { hex = '0' + hex }

	return Buffer.from(hex, 'hex').toString('base64')
}

const base64ToNumber = b64 => parseInt(Buffer.from(b64, 'base64').toString('hex'), 16)

const showcaseKeypair = keypair => keyType => async (type, options={}) => {
	const { print, save, file, header } = options
	if (print) console.log((header ? header : `${type} format:`).green)
	const [errors, key] = await keypair.to(type.toLowerCase())
	if (errors)
		return printErrors(errors)
	
	const val = keyType ? key[keyType] : key
	
	if (print) {
		if (typeof(val) == 'object')
			console.log(JSON.parse(JSON.stringify(val)))
		else
			console.log(val)
	}

	if (save) {
		const isJSON = typeof(val) == 'object'
		const origFileName = file || (isJSON ? 'key.json' : 'key.pem')
		const filePath = await getUniqueFileName(origFileName)
		await write(filePath, val)
	}
}

const jwtB64 = jwt => {
	if (!jwt || typeof(jwt) != 'object')
		return jwt 

	const b64Version = { ...jwt }
	if (jwt.e && typeof(jwt.e) == 'number')
		b64Version.e = numberToBase64(jwt.e)
	if (jwt.n && jwt.n instanceof Buffer)
		b64Version.n = jwt.n.toString('base64')
	if (jwt.d && jwt.d instanceof Buffer)
		b64Version.d = jwt.d.toString('base64')
	if (jwt.p && jwt.p instanceof Buffer)
		b64Version.p = jwt.p.toString('base64')
	if (jwt.q && jwt.q instanceof Buffer)
		b64Version.q = jwt.q.toString('base64')
	if (jwt.dmp1 && jwt.dmp1 instanceof Buffer)
		b64Version.dmp1 = jwt.dmp1.toString('base64')
	if (jwt.dmq1 && jwt.dmq1 instanceof Buffer)
		b64Version.dmq1 = jwt.dmq1.toString('base64')
	if (jwt.coeff && jwt.coeff instanceof Buffer)
		b64Version.coeff = jwt.coeff.toString('base64')
	if (jwt.dp && jwt.dp instanceof Buffer)
		b64Version.dp = jwt.dp.toString('base64')
	if (jwt.dq && jwt.dq instanceof Buffer)
		b64Version.dq = jwt.dq.toString('base64')
	if (jwt.qi && jwt.qi instanceof Buffer)
		b64Version.qi = jwt.qi.toString('base64')

	b64Version.qi = b64Version.qi || b64Version.coeff
	b64Version.coeff = b64Version.coeff || b64Version.qi
	b64Version.dmp1 = b64Version.dmp1 || b64Version.dp
	b64Version.dp = b64Version.dp || b64Version.dmp1
	b64Version.dmq1 = b64Version.dmq1 || b64Version.dq
	b64Version.dq = b64Version.dq || b64Version.dmq1

	return b64Version
}

const jwtBuffer = jwt => {
	if (!jwt || typeof(jwt) != 'object')
		return jwt 

	const buffVersion = { ...jwt }
	if (jwt.e && typeof(jwt.e) == 'string')
		buffVersion.e = base64ToNumber(jwt.e)
	if (jwt.n && typeof(jwt.n) == 'string')
		buffVersion.n = Buffer.from(jwt.n, 'base64')
	if (jwt.d && typeof(jwt.d) == 'string')
		buffVersion.d = Buffer.from(jwt.d, 'base64')
	if (jwt.p && typeof(jwt.p) == 'string')
		buffVersion.p = Buffer.from(jwt.p, 'base64')
	if (jwt.q && typeof(jwt.q) == 'string')
		buffVersion.q = Buffer.from(jwt.q, 'base64')
	if (jwt.dmp1 && typeof(jwt.dmp1) == 'string')
		buffVersion.dmp1 = Buffer.from(jwt.dmp1, 'base64')
	if (jwt.dmq1 && typeof(jwt.dmq1) == 'string')
		buffVersion.dmq1 = Buffer.from(jwt.dmq1, 'base64')
	if (jwt.coeff && typeof(jwt.coeff) == 'string')
		buffVersion.coeff = Buffer.from(jwt.coeff, 'base64')
	if (jwt.dp && typeof(jwt.dp) == 'string')
		buffVersion.dp = Buffer.from(jwt.dp, 'base64')
	if (jwt.dq && typeof(jwt.dq) == 'string')
		buffVersion.dq = Buffer.from(jwt.dq, 'base64')
	if (jwt.qi && typeof(jwt.qi) == 'string')
		buffVersion.qi = Buffer.from(jwt.qi, 'base64')

	buffVersion.qi = buffVersion.qi || buffVersion.coeff
	buffVersion.coeff = buffVersion.coeff || buffVersion.qi
	buffVersion.dmp1 = buffVersion.dmp1 || buffVersion.dp
	buffVersion.dp = buffVersion.dp || buffVersion.dmp1
	buffVersion.dmq1 = buffVersion.dmq1 || buffVersion.dq
	buffVersion.dq = buffVersion.dq || buffVersion.dmq1

	return buffVersion
}

const cleanJwk = jwk => {
	if (!jwk || typeof(jwk) != 'object')
		return 

	const keys = Object.keys(jwk)
	if (keys.indexOf('coeff') >= 0)
		delete jwk.coeff
	if (keys.indexOf('dmq1') >= 0)
		delete jwk.dmq1
	if (keys.indexOf('dmp1') >= 0)
		delete jwk.dmp1

	for (let key in jwk)
		if (!jwk[key])
			delete jwk[key]

	return jwk
}

const listPublicKeys = url => catchErrors((async () => {
	const { status, data } = await fetch.get({ uri: url })
	if (status == 404)
		throw new Error(`OpenID jwks_uri endpoint ${url} not found (status: 404)`)
	if (status >= 400)
		throw new Error(`Failed to GET OpenID jwks_uri data at ${url} (status: ${status}). Details: ${data && typeof(data) == 'object' ? JSON.stringify(data) : data}`)

	return data
})())

/**
 * HTTP GET public keys at OpenID url. This URL can either be the OpenID discovery endpoint, in which case, another HTTP GET
 * is done to the 'jwks_uri' endpoint, or it can be the 'jwks_uri'.
 * 
 * @param  {String} url	
 * 
 * @return {String} output.jwks_uri
 * @return {Object} output.keys
 */
const listOpenIDpublicKeys = url => catchErrors((async () => {
	const errorMsg = `Failed to GET OpenID public keys at ${url||'unknown URL'}`
	if (!url)
		throw new Error(`${errorMsg}. Missing required 'url'`)

	const { status, data } = await fetch.get({ uri: url })
	if (status == 404)
		throw new Error(`${errorMsg}(status: 404). OpenID discovery endpoint ${url} not found.`)
	if (status >= 400)
		throw new Error(`${errorMsg}(status: ${status}). Details: ${data && typeof(data) == 'object' ? JSON.stringify(data) : data}`)

	if (data.jwks_uri) {
		const [errors, keys] = await listPublicKeys(data.jwks_uri)
		if (errors)
			throw wrapErrors(errorMsg, errors)
		return { jwks_uri:data.jwks_uri, data:keys||{} }
	} else
		return { jwks_uri:url, data:data||{} }
})())

module.exports = {
	jwtBuffer,
	jwtB64,
	getDefaultChoice,
	requiredPrompt,
	EC_FULLY_SUPPORTED_CURVES,
	doesCurveSupportJwkFormat,
	showcaseKeypair,
	printErrors,
	numberToBase64,
	base64ToNumber,
	getEcCurves,
	getRsakeyLength: () => RSA_KEY_LENGTH,
	getCiphers: () => CIPHERS,
	cleanJwk,
	listOpenIDpublicKeys
}
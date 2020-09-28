const crypto = require('crypto')
require('colors')
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

const displayKeypair = keypair => keyType => async type => {
	console.log(`${type} format:`.green)
	const [errors, key] = await keypair.to(type.toLowerCase())
	if (errors)
		printErrors(errors)
	else {
		const val = key[keyType]
		if (typeof(val) == 'object')
			console.log(JSON.parse(JSON.stringify(val)))
		else
			console.log(val)
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

	return buffVersion
}

module.exports = {
	jwtBuffer,
	jwtB64,
	getDefaultChoice,
	requiredPrompt,
	EC_FULLY_SUPPORTED_CURVES,
	doesCurveSupportJwkFormat,
	displayKeypair,
	printErrors,
	numberToBase64,
	base64ToNumber,
	getEcCurves,
	getRsakeyLength: () => RSA_KEY_LENGTH,
	getCiphers: () => CIPHERS,
}
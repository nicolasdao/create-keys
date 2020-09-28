const { error:{ catchErrors, wrapErrors } } = require('puffy')

/**
 * Adds '0x00' to hex when its high order bit is 0x80 
 * 
 * @param  {String} hex
 * 
 * @return {String}
 */
const normalizeBigIntHex = hex => {
	const highOrderBit = parseInt(hex.slice(0, 2), 16)
	return (0x80 & highOrderBit) ? ('00' + hex) : hex
}

const nbrToUInt32Hex = nbr => {
	let hex = nbr.toString(16)
	while (hex.length < 8)
		hex = '0' + hex
	return hex
}

const padBytes = (hex, len) => {
	while (hex.length < len * 2)
		hex = '00' + hex
	return hex
}

/**
 * Official doc: https://tools.ietf.org/html/rfc4253#section-6.6
 * 
 * @param  {Object} jwk [description]
 * @return {[type]}     [description]
 */
const publicJwkToSsh = (jwk={}, comment) => catchErrors(() => {
	const errorMsg = 'Failed to convert public key from JWK to SSH format'

	if (!jwk.kty && !jwk.crv)
		throw new Error(`${errorMsg}. Invalid JWK format. Missing 'kty' or 'crv' property. Failed to determine the key's cipher.`)

	const [errors, ssh] = !jwk.crv ? publicRsaJwkToSsh(jwk, comment) : publicEcJwkToSsh(jwk, comment)
	if (errors)
		throw wrapErrors(errorMsg, errors)

	return ssh
})


const publicRsaJwkToSsh = (jwk={}, comment) => catchErrors(() => {
	const errorMsg = 'Failed to convert public RSA key from JWK to SSH format'

	// 1. Validates the input
	if (!jwk.e)
		throw new Error(`${errorMsg}. Missing required 'e'`)
	const et = typeof(jwk.e)
	if (et !== 'string' && !(jwk.e instanceof Buffer))
		throw new Error(`${errorMsg}. 'e' is expected to be a base64 string or a buffer, found ${et} instead.`)
	if (!jwk.n)
		throw new Error(`${errorMsg}. Missing required 'n'`)
	const nt = typeof(jwk.n)
	if (nt !== 'string' && !(jwk.n instanceof Buffer))
		throw new Error(`${errorMsg}. 'n' is expected to be a base64 string or a buffer, found ${nt} instead.`)

	// 2. Creates the SSH key
	const header = 'ssh-rsa'
	const hexBody = [
		Buffer.from(header, 'binary').toString('hex'),
		normalizeBigIntHex((et == 'string' ? Buffer.from(jwk.e, 'base64') : jwk.e).toString('hex')),
		normalizeBigIntHex((nt == 'string' ? Buffer.from(jwk.n, 'base64') : jwk.n).toString('hex'))
	]
		.map(hex => nbrToUInt32Hex(hex.length/2) + hex)
		.join('')

	const base64Body = Buffer.from(hexBody, 'hex').toString('base64')
	
	return `${header} ${base64Body}${comment ? ` ${comment}` : ''}`
})

const publicEcJwkToSsh = (jwk={}, comment) => catchErrors(() => {
	const errorMsg = 'Failed to convert public ECDSA key from JWK to SSH format'

	// 1. Validates the input
	if (!jwk.crv)
		throw new Error(`${errorMsg}. Missing required 'crv'`)
	if (jwk.crv != 'prime256v1' && jwk.crv != 'P-256' && jwk.crv != 'secp384r1' && jwk.crv != 'P-384')
		throw new Error(`${errorMsg}. 'crv' ${jwk.crv} is not supported. Supported curves: 'P-256' or 'P-384'`)
	const xt = typeof(jwk.x)
	if (xt !== 'string' && !(jwk.x instanceof Buffer))
		throw new Error(`${errorMsg}. 'x' is expected to be a base64 string or a buffer, found ${xt} instead.`)
	if (!jwk.y)
		throw new Error(`${errorMsg}. Missing required 'n'`)
	const yt = typeof(jwk.y)
	if (yt !== 'string' && !(jwk.y instanceof Buffer))
		throw new Error(`${errorMsg}. 'y' is expected to be a base64 string or a buffer, found ${yt} instead.`)

	const p256 = jwk.crv == 'prime256v1' || jwk.crv == 'P-256'
	const l = p256 ? 32 : 48
	const header = p256 ? 'ecdsa-sha2-nistp256' : 'ecdsa-sha2-nistp384'
	const hexCore = 
		'04' + 
		padBytes((xt == 'string' ? Buffer.from(jwk.x, 'base64') : jwk.x).toString('hex'), l) + 
		padBytes((yt == 'string' ? Buffer.from(jwk.y, 'base64') : jwk.y).toString('hex'), l)

	const hexBody = [
		Buffer.from(header, 'binary').toString('hex'),
		Buffer.from(p256 ? 'nistp256' : 'nistp384', 'binary').toString('hex'),
		hexCore
	]
		.map(hex => nbrToUInt32Hex(hex.length/2) + hex)
		.join('')

	const base64Body = Buffer.from(hexBody, 'hex').toString('base64')
	
	return `${header} ${base64Body}${comment ? ` ${comment}` : ''}`
})

const bufferToBase64Url = buff => buff.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

const publicSshToJwk = (sshKey='') => catchErrors(() => {
	const errorMsg = 'Failed to convert public key from SSH to JWK format'
	const [type, base64Body] = sshKey.split(/\s+/g)
	const buff = Buffer.from(base64Body, 'base64')
	
	const l = buff.length
	const offset = (buff.byteOffset || 0)
	let index = 0
	const dv = new DataView(buff.buffer.slice(offset, offset + l))
	const parts = []
	let el,len

	while (index < l) {
		len = dv.getUint32(index, false)
		index += 4
		if (0 === len) 
			continue

		el = buff.slice(index, index + len)
		if (0x00 === el[0])
			el = el.slice(1)
		
		parts.push(el)
		index += len
	}

	const isRSA = type.indexOf('rsa') >= 0
	const isP256 = type.indexOf('p256') >= 0
	const isP384 = type.indexOf('p384') >= 0

	if (!isRSA && !isP256 && !isP384)
		throw new Error(`${errorMsg}. Type ${type} is not supported. Supported types: 'ssh-rsa', 'ecdsa-sha2-nistp256' and 'ecdsa-sha2-nistp384'.`)

	if (isRSA)
		return {
			kty: 'RSA',
			e: bufferToBase64Url(parts[1]),
			n: bufferToBase64Url(parts[2])
		}
	else {
		const [length, jwk] = isP256 ? [32, { kty: 'EC', crv: 'P-256' }] : [48, { kty: 'EC', crv: 'P-384' }]
		jwk.x = bufferToBase64Url(parts[2].slice(1, 1 + length))
		jwk.y = bufferToBase64Url(parts[2].slice(1 + length, 1 + length + length))
		return jwk
	}

})

module.exports = {
	publicJwkToSsh,
	publicSshToJwk
}


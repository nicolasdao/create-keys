#!/usr/bin/env node

// NOTE: The official inquirer documentation is really good. To know more about the different question types,
// please refer to https://www.npmjs.com/package/inquirer#prompt-types

const program = require('commander')
const inquirer = require('inquirer')
require('colors')
const { version } = require('./package.json')
const { Keypair, Key } = require('./src')
const { getDefaultChoice, requiredPrompt, showcaseKeypair, getCiphers, getRsakeyLength, getEcCurves, listOpenIDpublicKeys, printErrors } = require('./src/utils')
const { getAbsolutePath, exists, read } = require('./src/file')
const { validate } = require('puffy')

const DEFAULT_EC_CURCE = 'prime256v1'
const DEFAULT_RSA_KEY_LENGTH = 2048

const voidFn = () => null

program.version(version) // This is required is you wish to support the --version option.

// 1. Creates your first command. This example shows an 'order' command with a required argument
// called 'product' and an optional argument called 'option'.
program
	.command('create')
	.alias('c') // Optional alias
	.description('Default behavior. Creates an asymmetric key pair. Equivalent to `npx create-keys`') // Optional description
	.action(async () => {
		const keyPairConfig = {}
		const { cipher } = await inquirer.prompt([
			{ type: 'list', name: 'cipher', message: 'Choose a cipher', choices: getCiphers() }
		])
		keyPairConfig.cipher = cipher
		const isRSA = cipher == 'rsa'

		if (isRSA) {
			const choices = getRsakeyLength()
			const { length } = await inquirer.prompt([
				{ type: 'list', name: 'length', message: 'Choose a key length', choices , default:getDefaultChoice(choices, DEFAULT_RSA_KEY_LENGTH) }
			])
			keyPairConfig.length = length
		} else if (cipher == 'ec') {
			const choices = getEcCurves()
			const { curve } = await inquirer.prompt([
				{ type: 'list', name: 'curve', message: 'Choose an ECDSA curve', choices, default:getDefaultChoice(choices, DEFAULT_EC_CURCE) }
			])
			keyPairConfig.curve = curve
		}

		const { protect } = await inquirer.prompt([
			{ type: 'confirm', name: 'protect', message: 'Do you want to protect the private key with a passphrase?', default: false }
		]) 

		if (protect) {
			const { passphrase } = await inquirer.prompt([{ type:'password', name:'passphrase', mask:'*', message:'Enter a passphrase' }])
			keyPairConfig.passphrase = passphrase
		}		

		const { formats } = await requiredPrompt(() => inquirer.prompt([
			{ type: 'checkbox', name: 'formats', message: 'Choose the output formats', choices:[
				{ name:'pem', value:'pem', checked:true }, 
				{ name:'jwk', value:'jwk', checked:false }] 
			}
		]), 'formats')
		keyPairConfig.formats = formats

		const pemSelected = formats.some(f => f == 'pem')
		const jwkSelected = formats.some(f => f == 'jwk')

		const { printOrSaveOptions=[] } = await requiredPrompt(() => inquirer.prompt([
			{ type: 'checkbox', name: 'printOrSaveOptions', message: 'Choose the output options', choices:[
				{ name:'Print in this terminal', value:'print', checked:true },
				{ name:'Save to files', value:'save' },
				{ name:'Both', value:'both' },
			] 
			}
		]), 'printOrSaveOptions')

		const printKeys = printOrSaveOptions.some(o => o == 'both' || o == 'print')
		const saveKeys = printOrSaveOptions.some(o => o == 'both' || o == 'save')
		const options = { print:printKeys, save:saveKeys }

		const keypair = new Keypair(keyPairConfig)

		const showcaseKey = showcaseKeypair(keypair)
		const showcasePrivateKey = showcaseKey('private')
		const showcasePublicKey = showcaseKey('public')

		if (printKeys) console.log('PRIVATE KEY'.green.underline.bold)
		if (pemSelected) 
			await showcasePrivateKey('PEM', { ...options, file:'private.key' })
		if (jwkSelected) 
			await showcasePrivateKey('JWK', { ...options, file:'private.json' })

		if (printKeys) console.log('PUBLIC KEY'.green.underline.bold)
		if (pemSelected) 
			await showcasePublicKey('PEM', { ...options, file:'public.pem' })
		if (jwkSelected) 
			await showcasePublicKey('JWK', { ...options, file:'public.json' })

	})

program
	.command('convert <filepath>')
	.alias('cv') // Optional alias
	.description('Converts a key file from PEM to JWK(i.e., JSON) or from JWK to PEM. Also support OpenID URL. Example: `npx create-keys cv private.json` or `npx create-keys cv https://accounts.google.com/.well-known/openid-configuration`')
	.action(async (filepath) => {
		const isUrl = validate.url(filepath)

		if (isUrl) {
			const [errors, result={}] = await listOpenIDpublicKeys(filepath)
			if (errors) {
				printErrors(errors)
				process.exit()
			}

			const { jwks_uri, data } = result

			const isNotArray = !Array.isArray(data.keys)
			if (!data.keys ||  isNotArray) {
				const msg = isNotArray 
					? `'keys' is expected to be an array of JWK. Found ${typeof(data.keys)} instead`
					: 'Could not found the \'keys\' property in the response'
				console.log(`WARN: ${msg}. Failed to convert JWK keys to PEM format`.yellow)
				console.log(`KEYS at ${jwks_uri}:`.green)
				console.log(JSON.stringify(data.keys, null, '  '))
			} else if (!data.keys.length) {
				console.log(`No public keys found at ${jwks_uri}`.cyan)
			} else {
				console.log(`Found ${data.keys.length} JWK public key${data.keys.length > 1 ? 's' : ''} at ${jwks_uri}`.cyan)
				const { printOrSaveOptions=[] } = await requiredPrompt(() => inquirer.prompt([
					{ type: 'checkbox', name: 'printOrSaveOptions', message: 'Choose the output options', choices:[
						{ name:'Print in this terminal', value:'print', checked:true },
						{ name:'Save to files', value:'save' },
						{ name:'Both', value:'both' },
					] 
					}
				]), 'printOrSaveOptions')

				const printKeys = printOrSaveOptions.some(o => o == 'both' || o == 'print')
				const saveKeys = printOrSaveOptions.some(o => o == 'both' || o == 'save')
				const options = { print:printKeys, save:saveKeys }

				for (let jwk of data.keys) {
					const showcaseKey = showcaseKeypair(new Key({ jwk }))()
					const kid = jwk.kid||'no_kid'
					const alg = jwk.alg||'no_alg'
					const kty = jwk.kty||'no_kty'
					const filename = `${kty}-${alg}-kid_${kid}.pem`.toLowerCase()
					await showcaseKey('PEM', { ...options, header: filename , file:filename })
				}
			}
		} else {
			const file = getAbsolutePath(filepath)
			const fileExists = await exists(file)
			if (!fileExists) {
				console.log(`File ${file} not found`.red)
				process.exit()
			}			

			const fileContent = (await read(file)).toString()

			let jwkContent 
			try {
				jwkContent = JSON.parse(fileContent)
			} catch(err) {
				jwkContent = null
				voidFn(err)
			}

			const keyConfig = jwkContent ? { jwk:jwkContent } : { pem:fileContent }
			const [outputFormat, outputFile] = jwkContent ? ['PEM', 'key.pem'] : ['JWK', 'key.json']

			const { printOrSaveOptions=[] } = await requiredPrompt(() => inquirer.prompt([
				{ type: 'checkbox', name: 'printOrSaveOptions', message: 'Choose the output options', choices:[
					{ name:'Print in this terminal', value:'print', checked:true },
					{ name:'Save to files', value:'save' },
					{ name:'Both', value:'both' },
				] 
				}
			]), 'printOrSaveOptions')
			
			const printKeys = printOrSaveOptions.some(o => o == 'both' || o == 'print')
			const saveKeys = printOrSaveOptions.some(o => o == 'both' || o == 'save')
			const options = { print:printKeys, save:saveKeys }

			const showcaseKey = showcaseKeypair(new Key(keyConfig))()

			await showcaseKey(outputFormat, { ...options, file:outputFile })
		}
	})

program
	.command('list <url>')
	.alias('ls') // Optional alias
	.description('List the public keys of an OpenID discovery endpoint. Example: `npx create-keys ls https://accounts.google.com/.well-known/openid-configuration`')
	.action(async (url) => {
		const [errors, result={}] = await listOpenIDpublicKeys(url)
		if (errors) {
			printErrors(errors)
			process.exit()
		}

		const { jwks_uri, data } = result

		console.log(`KEYS at ${jwks_uri}:`.green)
		console.log(JSON.stringify(data, null, '  '))
	})


// 2. Deals with cases where no command is passed.
if (process.argv.length == 2)
	process.argv.push('create')

// 3. Starts the commander program
program.parse(process.argv) 






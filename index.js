#!/usr/bin/env node

// NOTE: The official inquirer documentation is really good. To know more about the different question types,
// please refer to https://www.npmjs.com/package/inquirer#prompt-types

const program = require('commander')
const inquirer = require('inquirer')
require('colors')
const { version } = require('./package.json')
const { Keypair } = require('./src')
const { getDefaultChoice, requiredPrompt, displayKeypair, getCiphers, getRsakeyLength, getEcCurves } = require('./src/utils')

const DEFAULT_EC_CURCE = 'prime256v1'
const DEFAULT_RSA_KEY_LENGTH = 2048

program.version(version) // This is required is you wish to support the --version option.

// 1. Creates your first command. This example shows an 'order' command with a required argument
// called 'product' and an optional argument called 'option'.
program
	.command('create')
	.alias('c') // Optional alias
	.description('Creates an asymmetric key pair') // Optional description
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

		const showPem = formats.some(f => f == 'pem')
		const showJwk = formats.some(f => f == 'jwk')

		const keypair = new Keypair(keyPairConfig)
		const displayKey = displayKeypair(keypair)
		const displayPrivateKey = displayKey('private')
		const displayPublicKey = displayKey('public')

		console.log('PRIVATE KEY'.green.underline.bold)
		if (showPem) 
			await displayPrivateKey('PEM')
		if (showJwk) 
			await displayPrivateKey('JWK')

		console.log('PUBLIC KEY'.green.underline.bold)
		if (showPem) 
			await displayPublicKey('PEM')
		if (showJwk) 
			await displayPublicKey('JWK')

	})


// 2. Deals with cases where no command is passed.
if (process.argv.length == 2)
	process.argv.push('create')

// 3. Starts the commander program
program.parse(process.argv) 






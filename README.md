# create-key

Terminal assistant to generate or read cryptographic keys. This utility was created out of frustration, as more time was spent Googling _how to use openssl_ rather than getting things done. This utility is originally aimed to be used via `npx`, but it can also be used in NodeJS programs. It is not as powerful as openssl as it only support RSA and ECDSA ciphers. Thanks to `npx`, there is no need to install this utility, just make sure that `npm` > 5.2 is installed and then run:

```
npx create-keys
```

This command starts a terminal questionnaire that helps building the keys you need. 

Currently, this package only supports the following:
- Ciphers: RSA or ECDSA
- Encoding: PCKS8 for private keys, PCKS1 for RSA public keys and SPKI for ECDSA public keys
- ECDSA curves: P-256 (prime256v1) and P-384 (secp384r1)
- Output formats: PEM and JWK

# Table of contents

> * [CLI](#cli)
>	- [Creating new keys](#creating-new-keys)
>	- [Converting from one format to another](#converting-from-one-format-to-another)
>	- [Listing OpenID JWK public keys using an OpenID discovery endpoint](#listing-openid-jwk-public-keys-using-an-openid-discovery-endpoint)
>	- [Converting OpenID JWK public keys to PEM files](#converting-openid-jwk-public-keys-to-pem-files)
> * [Using it in Node](#using-it-in-node)

# CLI

For any help with the CLI, use:

```
npx create-keys help
```

## Creating new keys

```
npx create-keys
```

## Converting from one format to another

```
npx create-keys convert private.pem
```

or 

```
npx create-keys convert private.json
```

`create-keys` automatically detectects the format (PEM vs JWK), the type (private vs public keys) and the cipher (RSA vs ECDSA). 

## Listing OpenID JWK public keys using an OpenID discovery endpoint

```
npx create-keys list https://accounts.google.com/.well-known/openid-configuration
```

or 

```
npx create-keys list https://www.googleapis.com/oauth2/v3/certs
```

`create-keys` supports both an OpenID discovery endpoint or the direct `jwks_uri` endpoint. 

## Converting OpenID JWK public keys to PEM files

```
npx create-keys convert https://accounts.google.com/.well-known/openid-configuration
```

or 

```
npx create-keys convert https://www.googleapis.com/oauth2/v3/certs
```

`create-keys` supports both an OpenID discovery endpoint or the direct `jwks_uri` endpoint. 

# Using it in Node

1. Install:
```
npm i create-keys
```
2. In your code:
```js
const { Keypair, Key } = require('create-keys')

const rsaKeypair = new Keypair({ cipher:'rsa', length:1024 })
const ecKeypair = new Keypair({ cipher:'ec', curve:'prime256v1' }) // supported curves: 'prime256v1' and 'secp384r1'

const main = async () => {
	// Creates RSA key pair
	const [rsaPemErrors, rsaPemKeys] = await rsaKeypair.to('pem')
	const [rsaJwkErrors, rsaJwkKeys] = await rsaKeypair.to('jwk')

	// Creates ECDSA key pair
	const [ecPemErrors, ecPemKeys] = await ecKeypair.to('pem')
	const [ecJwkErrors, ecJwkKeys] = await ecKeypair.to('jwk')

	console.log('RSA PRIVATE PEM')
	console.log(rsaPemKeys.private)
	console.log('RSA PUBLIC PEM')
	console.log(rsaPemKeys.public)

	console.log('RSA PRIVATE JWK')
	console.log(JSON.stringify(rsaJwkKeys.private, null, '  '))
	console.log('RSA PUBLIC JWK')
	console.log(JSON.stringify(rsaJwkKeys.public, null, '  '))

	console.log('ECDSA PRIVATE PEM')
	console.log(ecPemKeys.private)
	console.log('ECDSA PUBLIC PEM')
	console.log(ecPemKeys.public)

	console.log('ECDSA PRIVATE JWK')
	console.log(JSON.stringify(ecJwkKeys.private, null, '  '))
	console.log('ECDSA PUBLIC JWK')
	console.log(JSON.stringify(ecJwkKeys.public, null, '  '))

	const [rsaPrivateJwkErros, rsaPrivateJwk] = new Key({ pem:rsaPemKeys.private }).to('jwk')
	console.log('RSA PRIVATE PEM TO JWK')
	console.log(JSON.stringify(rsaPrivateJwk, null, '  '))

	const [ecPublicPemErrors, ecPublicPem] = new Key({ jwk:ecJwkKeys.public }).to('pem')
	console.log('ECDSA PUBLIC JWK TO PEM')
	console.log(ecPublicPem)
}

main()
```




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



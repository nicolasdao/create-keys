# create-key

Terminal assistant to generate or read cryptographic keys. This utility was created out of frustration, as more time is spent Googling _how to use openssl_ instead of getting things done. This utility is originally aimed to be used via `npx`, but it can also be used in NodeJS programs. It is not as powerful as openssl as it only support RSA and ECDSA ciphers. Thanks to `npx`, there is no need to install this utility, just make sure that `npm` > 5.2 is installed and then run:

```
npx create-keys
```

This command starts a terminal questionnaire that helps building the keys you need.

# Table of contents



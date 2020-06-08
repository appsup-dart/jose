
## 0.1.3

- Support RSAES-OAEP
- Allow x509 parameters in JWK
- JsonWebAlgorithm class
- Generating random non-symmetric keys
- cryptoKeyPair getter on JsonWebKey returning a `KeyPair` from `crypto_keys` package 

## 0.1.2

- Add `allowedAlgorithms` argument also in JWT

## 0.1.1

- Fix security issue: JWS with algorithm `none` was previously verified, 
now you can specify which algorithms are allowed and by default `none` is 
not allowed.  

## 0.1.0

- Initial version

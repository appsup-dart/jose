## 1.0.0

- Migrate null safety

## 0.2.1+1

- Fix docs

## 0.2.1

- Added JsonWebKey constructors for creating EC and RSA keys
- Added factory constructor for creating a JsonWebKey from crypto keys
- Added factory constructor for creating a JsonWebKey from a pem string
- Support for P-256K curve 

## 0.2.0

- Support RSAES-OAEP
- Allow x509 parameters in JWK
- JsonWebAlgorithm class
- Generating random non-symmetric keys
- cryptoKeyPair getter on JsonWebKey returning a `KeyPair` from `crypto_keys` package
- **Breaking Change**: loading jwk set from `package` or `file` url no longer supported by default. The new class 
`JsonWebKeySetLoader` can be used to override this behavior or manage the way jwk sets are loaded from an url. 

## 0.1.2

- Add `allowedAlgorithms` argument also in JWT

## 0.1.1

- Fix security issue: JWS with algorithm `none` was previously verified, 
now you can specify which algorithms are allowed and by default `none` is 
not allowed.  

## 0.1.0

- Initial version

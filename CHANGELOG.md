## 0.4.0
 - **FIX**: use `x509_plus` and `crypto_keys_plus`.
## 0.3.5

 - **FIX**: allow double values when converting to DateTime and Duration (pull request [#33](https://github.com/appsup-dart/jose/issues/33) from PixelToast). ([3b204b10](https://github.com/appsup-dart/jose/commit/3b204b10101c7db7dc275279dcc4090a1494d238))
 - **FIX**: type mismatch error on keyOperations getter (pull request [#37](https://github.com/appsup-dart/jose/issues/37) from samataro). ([8afde0fd](https://github.com/appsup-dart/jose/commit/8afde0fda8f0e5232e115dbeff25d2367b7521cb))
 - **FIX**: add missing keyId when constructing a JWK with EcPublicKey (pull request [#38](https://github.com/appsup-dart/jose/issues/38) from tallinn1960). ([b8d11f32](https://github.com/appsup-dart/jose/commit/b8d11f325914ead348ae97fa7e344eb3dca7ee8f))
 - **FIX**: use 12 byte iv with AESGCM (pull request [#39](https://github.com/appsup-dart/jose/issues/39) from tallinn1960). ([5b7e24da](https://github.com/appsup-dart/jose/commit/5b7e24da01fc3e782203ace5be9752055b54b33d))
 - **FIX**: make unprotected header in JWE optional (pull request [#43](https://github.com/appsup-dart/jose/issues/43) from heacare). ([aefeeb04](https://github.com/appsup-dart/jose/commit/aefeeb043fd5203314a691deaece87fb4fbc54c2))
 - **FEAT**: publish jose_plus. ([35d44717](https://github.com/appsup-dart/jose/commit/35d44717e8175f50c26d9221bdcdc06aee46871b))
 - **FEAT**: add support for es256k algorithm. ([a2d046a3](https://github.com/appsup-dart/jose/commit/a2d046a334a9060fc258610ce2e23c4865bfa3b3))

## 0.3.4

 - **FEAT**: Support latest `package:http` ([#50](https://github.com/appsup-dart/jose/pull/50))


## 0.3.3

 - **FIX**: allow double values when converting to DateTime and Duration (pull request [#33](https://github.com/appsup-dart/jose/issues/33) from PixelToast). ([3b204b10](https://github.com/appsup-dart/jose/commit/3b204b10101c7db7dc275279dcc4090a1494d238))
 - **FIX**: type mismatch error on keyOperations getter (pull request [#37](https://github.com/appsup-dart/jose/issues/37) from samataro). ([8afde0fd](https://github.com/appsup-dart/jose/commit/8afde0fda8f0e5232e115dbeff25d2367b7521cb))
 - **FIX**: add missing keyId when constructing a JWK with EcPublicKey (pull request [#38](https://github.com/appsup-dart/jose/issues/38) from tallinn1960). ([b8d11f32](https://github.com/appsup-dart/jose/commit/b8d11f325914ead348ae97fa7e344eb3dca7ee8f))
 - **FIX**: use 12 byte iv with AESGCM (pull request [#39](https://github.com/appsup-dart/jose/issues/39) from tallinn1960). ([5b7e24da](https://github.com/appsup-dart/jose/commit/5b7e24da01fc3e782203ace5be9752055b54b33d))
 - **FIX**: make unprotected header in JWE optional (pull request [#43](https://github.com/appsup-dart/jose/issues/43) from heacare). ([aefeeb04](https://github.com/appsup-dart/jose/commit/aefeeb043fd5203314a691deaece87fb4fbc54c2))
 - **FEAT**: add support for es256k algorithm. ([a2d046a3](https://github.com/appsup-dart/jose/commit/a2d046a334a9060fc258610ce2e23c4865bfa3b3))


## 0.3.2

- Compatible with version `0.3.0` of `crypto_keys`

## 0.3.1

- JsonWebKey.parsePem handles CERTIFICATE
- `DefaultJsonWebKeySetLoader`: if possible, use HTTP headers to determine cache expiration. 

## 0.3.0

- Migrate null safety

## 0.2.2
- Bump `asn1lib` to 0.8.1.

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

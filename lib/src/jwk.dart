/// [JSON Web Key](https://tools.ietf.org/html/rfc7517)
library jose.jwk;

import 'package:crypto_keys/crypto_keys.dart';
import 'util.dart';
import 'dart:async';
import 'jose.dart';
// temporarily use copy of resource package
// until issue https://github.com/dart-lang/resource/issues/35 has been fixed
import 'resource/resource.dart';
import 'dart:convert' as convert;

/// JSON Web Key (JWK) represents a cryptographic key
class JsonWebKey extends JsonObject {
  final KeyPair _keyPair;

  /// Constructs a [JsonWebKey] from its JSON representation
  JsonWebKey.fromJson(Map<String, dynamic> json)
      : _keyPair = new KeyPair.fromJwk(json),
        super.from(json) {
    if (keyType == null) throw new ArgumentError.notNull("keyType");
    if (json.containsKey("x5u") ||
        json.containsKey("x5c") ||
        json.containsKey("x5t") ||
        json.containsKey("x5t#S256"))
      throw new UnimplementedError("X.509 keys not implemented");
  }

  static const _keyBitLengthByEncAlg = {
    "A128CBC-HS256": 256,
    "A192CBC-HS384": 384,
    "A256CBC-HS512": 512,
    "A128GCM": 256,
    "A192GCM": 384,
    "A256GCM": 512
  };

  /// Generates a random symmetric key suitable for the specified [algorithm]
  factory JsonWebKey.generate(String algorithm) {
    var bitLength = _keyBitLengthByEncAlg[algorithm];
    var keyPair = new KeyPair.generateSymmetric(bitLength);
    return new JsonWebKey.fromJson({
      "kty": "oct",
      "k": encodeBase64EncodedBytes(
          (keyPair.publicKey as SymmetricKey).keyValue),
      "alg": algorithm,
      "use": "enc",
      "keyOperations": ["encrypt", "decrypt"]
    });
  }

  /// The cryptographic algorithm family used with the key, such as `RSA` or
  /// `EC`.
  String get keyType => this["kty"];

  /// The intended use of the public key.
  ///
  /// Values defined by the specification are:
  ///
  /// * `sig` (signature)
  /// * `enc` (encryption)
  ///
  /// Other values MAY be used.
  ///
  String get publicKeyUse => this["use"];

  /// The operation(s) that the key is intended to be used for.
  ///
  /// Values defined by the specification are:
  ///
  /// * `sign` (compute digital signature or MAC)
  /// * `verify` (verify digital signature or MAC)
  /// * `encrypt` (encrypt content)
  /// * `decrypt` (decrypt content and validate decryption, if applicable)
  /// * `wrapKey` (encrypt key)
  /// * `unwrapKey` (decrypt key and validate decryption, if applicable)
  /// * `deriveKey` (derive key)
  /// * `deriveBits` (derive bits not to be used as a key)
  ///
  /// Other values MAY be used.
  Set<String> get keyOperations => getTypedList("key_ops")?.toSet();

  /// The algorithm intended for use with the key.
  String get algorithm => this["alg"];

  /// Key ID used to match a specific key.
  ///
  /// This is used, for instance, to choose among a set of keys within a JWK Set
  /// during key rollover.
  String get keyId => this["kid"];

/*
  TODO: implement X.509

  /// A resource for an X.509 public key certificate or certificate chain.
  Uri get x509Url => _json["x5u"]==null ? null : Uri.parse(_json["x5u"]);

  /// A chain of one or more PKIX certificates.
  dynamic get x509CertificateChain => _json["x5c"];

  /// A base64url encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding
  /// of an X.509 certificate.
  String get x509CertificateThumbprint => _json["x5t"];

  /// A base64url encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding
  /// of an X.509 certificate.
  String get x509CertificateSha256Thumbprint => _json["x5t#S256"];
*/

  /// Compute digital signature or MAC
  List<int> sign(List<int> data, {String algorithm}) {
    _assertCanDo("sign");
    var signer = _keyPair.privateKey.createSigner(_getAlgorithm(algorithm));
    var signature = signer.sign(data);
    return signature.data;
  }

  /// Verify digital signature or MAC
  bool verify(List<int> data, List<int> signature, {String algorithm}) {
    _assertCanDo("verify");
    var verifier = _keyPair.publicKey.createVerifier(_getAlgorithm(algorithm));
    return verifier.verify(data, new Signature(signature));
  }

  /// Encrypt content
  EncryptionResult encrypt(List<int> data,
      {List<int> initializationVector,
      List<int> additionalAuthenticatedData,
      String algorithm}) {
    _assertCanDo("encrypt");
    algorithm ??= this.algorithm;
    var encrypter =
        _keyPair.publicKey.createEncrypter(_getAlgorithm(algorithm));
    return encrypter.encrypt(data,
        initializationVector: initializationVector,
        additionalAuthenticatedData: additionalAuthenticatedData);
  }

  /// Decrypt content and validate decryption, if applicable
  List<int> decrypt(List<int> data,
      {List<int> initializationVector,
      List<int> authenticationTag,
      List<int> additionalAuthenticatedData,
      String algorithm}) {
    _assertCanDo("decrypt");
    algorithm ??= this.algorithm;
    var decrypter =
        _keyPair.privateKey.createEncrypter(_getAlgorithm(algorithm));
    return decrypter.decrypt(new EncryptionResult(data,
        initializationVector: initializationVector,
        authenticationTag: authenticationTag,
        additionalAuthenticatedData: additionalAuthenticatedData));
  }

  /// Encrypt key
  List<int> wrapKey(JsonWebKey key, {String algorithm}) {
    _assertCanDo("wrapKey");
    if (key.keyType != "oct")
      throw new UnsupportedError("Can only wrap symmetric keys");
    algorithm ??= this.algorithm;
    var encrypter =
        _keyPair.publicKey.createEncrypter(_getAlgorithm(algorithm));
    var v = encrypter.encrypt(decodeBase64EncodedBytes(key["k"]));
    return v.data;
  }

  /// Decrypt key and validate decryption, if applicable
  JsonWebKey unwrapKey(List<int> data, {String algorithm}) {
    _assertCanDo("unwrapKey");
    algorithm ??= this.algorithm;
    var decrypter =
        _keyPair.privateKey.createEncrypter(_getAlgorithm(algorithm));
    var v = decrypter.decrypt(new EncryptionResult(data));
    return new JsonWebKey.fromJson({
      "kty": "oct",
      "k": encodeBase64EncodedBytes(v),
      "use": "enc",
      "keyOperations": ["encrypt", "decrypt"]
    });
  }

  /// Returns true if this key can be used with the JSON Web Algorithm
  /// identified by [algorithm]
  bool usableForAlgorithm(String algorithm) {
    if (this.algorithm != null && this.algorithm != algorithm) return false;
    switch (algorithm) {
      // Algorithms for JWS

      /// HMAC using SHA-256
      case "HS256":

      /// HMAC using SHA-384
      case "HS384":

      /// HMAC using SHA-512
      case "HS512":
        return keyType == "oct";

      /// RSASSA-PKCS1-v1_5 using SHA-256
      case "RS256":

      /// RSASSA-PKCS1-v1_5 using SHA-384
      case "RS384":

      /// RSASSA-PKCS1-v1_5 using SHA-512
      case "RS512":
        return keyType == "RSA";

      /// ECDSA using P-256 and SHA-256
      case "ES256":

      /// ECDSA using P-384 and SHA-384
      case "ES384":

      /// ECDSA using P-521 and SHA-512
      case "ES512":
        return keyType == "EC";

      /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
      case "PS256":

      /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
      case "PS384":

      /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
      case "PS512":
        return null;

      /// No digital signature or MAC
      case "none":
        return null;
      // Algorithms for JWE
      /// RSAES-PKCS1-v1_5
      case "RSA1_5":

      /// RSAES OAEP using default parameters
      case "RSA-OAEP":

      /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
      case "RSA-OAEP-256":
        return keyType == "RSA";

      /// AES Key Wrap with default initial value using 128-bit key
      case "A128KW":

      /// AES Key Wrap with default initial value using 192-bit key
      case "A192KW":

      /// AES Key Wrap with default initial value using 256-bit key
      case "A256KW":
        return keyType == "oct";

      /// Direct use of a shared symmetric key as the CEK
      case "dir":
        return null;

      /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
      case "ECDH-ES":

      /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
      case "ECDH-ES+A128KW":

      /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
      case "ECDH-ES+A192KW":

      /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
      case "ECDH-ES+A256KW":

      /// Key wrapping with AES GCM using 128-bit key
      case "A128GCMKW":

      /// Key wrapping with AES GCM using 192-bit key
      case "A192GCMKW":

      /// Key wrapping with AES GCM using 256-bit key
      case "A256GCMKW":

      /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
      case "PBES2-HS256+A128KW":

      /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
      case "PBES2-HS384+A192KW":

      /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
      case "PBES2-HS512+A256KW":
        return null;

      // Encryption Algorithms for JWE
      /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
      case "A128CBC-HS256":

      /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
      case "A192CBC-HS384":

      /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
      case "A256CBC-HS512":

      /// AES GCM using 128-bit key
      case "A128GCM":

      /// AES GCM using 192-bit key
      case "A192GCM":

      /// AES GCM using 256-bit key
      case "A256GCM":
        return keyType == "oct";
    }
    return false;
  }

  /// Returns true if this key can be used for the [operation]
  ///
  /// The value of [operation] should be one of the possible values for
  /// [keyOperations].
  bool usableForOperation(String operation) {
    var ops = keyOperations;
    if (ops != null && !ops.contains(operation)) return false;
    if (publicKeyUse != null) {
      switch (operation) {
        case "sign":
        case "verify":
          if (publicKeyUse != "sig") return false;
          break;
        case "encrypt":
        case "decrypt":
        case "wrapKey":
        case "unwrapKey":
          if (publicKeyUse != "enc") return false;
          break;
      }
    }
    switch (operation) {
      case "sign":
      case "unwrapKey":
      case "decrypt":
        return _keyPair.privateKey != null;
      case "verify":
      case "wrapKey":
      case "encrypt":
        return _keyPair.publicKey != null;
    }
    return false;
  }

  /// Returns a JSON Web Algorithm name that can be used with this key for
  /// [operation]
  String algorithmForOperation(String operation) {
    if (!usableForOperation(operation)) return null;
    if (algorithm != null) return algorithm;
    switch (operation) {
      case "sign":
      case "verify":
        // TODO: use key length
        switch (keyType) {
          case "oct":
            return "HS256";
          case "RSA":
            return "RS256";
          case "EC":
            return "ES256";
        }
        return null;
      case "wrapKey":
      case "unwrapKey":
        // TODO: use key length
        switch (keyType) {
          case "oct":
            return "A128KW";
          case "RSA":
            return "RSA1_5";
          case "EC":
            return null;
        }
        return null;
      case "encrypt":
      case "decrypt":
        switch (keyType) {
          case "oct":
            return "A128CBC-HS256";
          case "RSA":
          case "EC":
            return null;
        }
        return null;
    }
    return null;
  }

  AlgorithmIdentifier _getAlgorithm(String algorithm) {
    if (this["alg"] != null) {
      if (this["alg"] != algorithm) {
        throw new ArgumentError.value(algorithm, "algorithm",
            "Algorithm should match key algorithm '${this["alg"]}'");
      }
    }
    algorithm ??= this["alg"];
    return algorithm == null
        ? null
        : AlgorithmIdentifier.getByJwaName(algorithm);
  }

  void _assertCanDo(String op) {
    if (!usableForOperation(op)) {
      throw new StateError(
          "This JsonWebKey does not support the '$op' operation.");
    }
  }
}

/// Represents a set of [JsonWebKey]s
class JsonWebKeySet extends JsonObject {
  /// An array of JWK values
  List<JsonWebKey> get keys =>
      getTypedList("keys", factory: (v) => new JsonWebKey.fromJson(v));

  /// Constructs a [JsonWebKeySet] from the list of [keys]
  factory JsonWebKeySet.fromKeys(Iterable<JsonWebKey> keys) =>
      new JsonWebKeySet.fromJson(
          {"keys": keys.map((v) => v.toJson()).toList()});

  /// Constructs a [JsonWebKeySet] from its JSON representation
  JsonWebKeySet.fromJson(Map<String, dynamic> json) : super.from(json);
}

/// A key store to lookup [JsonWebKey]s
class JsonWebKeyStore {
  final List<JsonWebKey> _keys = [];
  final List<JsonWebKeySet> _keySets = [];
  final List<Uri> _keySetUrls = [];

  final Map<Uri, JsonWebKeySet> _keySetCache = {};

  /// Adds a key set to this tore
  void addKeySet(JsonWebKeySet keys) => _keySets.add(keys);

  /// Adds a key to this store
  void addKey(JsonWebKey key) => _keys.add(key);

  /// Adds a key set url to this store
  void addKeySetUrl(Uri url) => _keySetUrls.add(url);

  /// Find [JsonWebKey]s for a [JoseObject] with header [header].
  ///
  /// See also [https://tools.ietf.org/html/rfc7515#appendix-D]
  Stream<JsonWebKey> findJsonWebKeys(JoseHeader header, String operation) {
    if (header.algorithm == "none") return new Stream.fromIterable([null]);
    return _allKeys(header)
        .where((key) => _isValidKeyFor(key, header, operation));
  }

  Stream<JsonWebKey> _allKeys(JoseHeader header) async* {
    // The key provided by the "jwk"
    if (header.jsonWebKey != null) yield header.jsonWebKey;
    // Other applicable keys available to the application
    yield* new Stream.fromIterable(_keys);
    for (var s in _keySets) {
      yield* new Stream.fromIterable(s.keys);
    }
/*
    // TODO trust keys from header?
    // Keys referenced by the "jku"
    if (header.jwkSetUrl != null) yield* _keysFromSet(header.jwkSetUrl);
    // The key referenced by the "x5u"
    // TODO
    // The key provided by the "x5c"
    // TODO
*/
    // Other applicable keys available to the application
    for (var url in _keySetUrls) {
      yield* _keysFromSet(url);
    }
  }

  bool _isValidKeyFor(JsonWebKey key, JoseHeader header, String operation) {
    if (header.keyId != key.keyId) return false;
    return key.usableForAlgorithm(
            operation == "encrypt" || operation == "decrypt"
                ? header.encryptionAlgorithm
                : header.algorithm) &&
        key.usableForOperation(operation);
  }

  Stream<JsonWebKey> _keysFromSet(Uri uri) async* {
    var set = _findKeySetFromCache(uri);
    if (set == null) {
      try {
        var v = await new Resource(uri).readAsString();
        set = _addKeySetToCache(
            uri, new JsonWebKeySet.fromJson(convert.json.decode(v)));
      } catch (e) {
        // TODO log
        return;
      }
    }
    yield* new Stream.fromIterable(set.keys);
  }

  JsonWebKeySet _addKeySetToCache(Uri uri, JsonWebKeySet set) =>
      _keySetCache[uri] = set;

  JsonWebKeySet _findKeySetFromCache(Uri uri) => _keySetCache[uri];
}

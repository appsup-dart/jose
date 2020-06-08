/// [JSON Web Key](https://tools.ietf.org/html/rfc7517)
library jose.jwk;

import 'package:crypto_keys/crypto_keys.dart';
import 'package:jose/src/jwa.dart';
import 'package:x509/x509.dart' as x509;
import 'util.dart';
import 'dart:async';
import 'jose.dart';
// temporarily use copy of resource package
// until issue https://github.com/dart-lang/resource/issues/35 has been fixed
import 'resource/resource.dart';
import 'dart:convert' as convert;
import 'package:asn1lib/asn1lib.dart';

/// JSON Web Key (JWK) represents a cryptographic key
class JsonWebKey extends JsonObject {
  final KeyPair _keyPair;

  /// Constructs a [JsonWebKey] from its JSON representation
  JsonWebKey.fromJson(Map<String, dynamic> json)
      : _keyPair = KeyPair.fromJwk(json),
        super.from(json) {
    if (keyType == null) throw ArgumentError.notNull('keyType');
    if (x509CertificateChain != null && x509CertificateChain.isNotEmpty) {
      var cert = x509CertificateChain.first;

      if (_keyPair.publicKey != cert.publicKey) {
        throw ArgumentError("The public key in 'x5c' does not match this key.");
      }
    }
  }

  /// Generates a random key suitable for the specified [algorithm]
  factory JsonWebKey.generate(String algorithm, {int keyBitLength}) {
    var alg = JsonWebAlgorithm.getByName(algorithm);
    return alg.generateRandomKey(keyBitLength: keyBitLength);
  }

  KeyPair get cryptoKeyPair => _keyPair;

  /// The cryptographic algorithm family used with the key, such as `RSA` or
  /// `EC`.
  String get keyType => this['kty'];

  /// The intended use of the public key.
  ///
  /// Values defined by the specification are:
  ///
  /// * `sig` (signature)
  /// * `enc` (encryption)
  ///
  /// Other values MAY be used.
  ///
  String get publicKeyUse => this['use'];

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
  Set<String> get keyOperations => getTypedList('key_ops')?.toSet();

  /// The algorithm intended for use with the key.
  String get algorithm => this['alg'];

  /// Key ID used to match a specific key.
  ///
  /// This is used, for instance, to choose among a set of keys within a JWK Set
  /// during key rollover.
  String get keyId => this['kid'];

  /// A resource for an X.509 public key certificate or certificate chain.
  Uri get x509Url => this['x5u'] == null ? null : Uri.parse(this['x5u']);

  /// A chain of one or more PKIX certificates.
  List<x509.X509Certificate> get x509CertificateChain =>
      (this['x5c'] as List)?.map((v) {
        var bytes = convert.base64.decode(v);
        var p = ASN1Parser(bytes);
        var o = p.nextObject();
        if (o is! ASN1Sequence) {
          throw FormatException('Expected SEQUENCE, got ${o.runtimeType}');
        }
        var s = o as ASN1Sequence;
        return x509.X509Certificate.fromAsn1(s);
      })?.toList();

  /// A base64url encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding
  /// of an X.509 certificate.
  String get x509CertificateThumbprint => this['x5t'];

  /// A base64url encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding
  /// of an X.509 certificate.
  String get x509CertificateSha256Thumbprint => this['x5t#S256'];

  /// Compute digital signature or MAC
  List<int> sign(List<int> data, {String algorithm}) {
    _assertCanDo('sign');
    var signer = _keyPair.privateKey.createSigner(_getAlgorithm(algorithm));
    var signature = signer.sign(data);
    return signature.data;
  }

  /// Verify digital signature or MAC
  bool verify(List<int> data, List<int> signature, {String algorithm}) {
    _assertCanDo('verify');
    var verifier = _keyPair.publicKey.createVerifier(_getAlgorithm(algorithm));
    return verifier.verify(data, Signature(signature));
  }

  /// Encrypt content
  EncryptionResult encrypt(List<int> data,
      {List<int> initializationVector,
      List<int> additionalAuthenticatedData,
      String algorithm}) {
    _assertCanDo('encrypt');
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
    _assertCanDo('decrypt');
    algorithm ??= this.algorithm;
    var decrypter =
        _keyPair.privateKey.createEncrypter(_getAlgorithm(algorithm));
    return decrypter.decrypt(EncryptionResult(data,
        initializationVector: initializationVector,
        authenticationTag: authenticationTag,
        additionalAuthenticatedData: additionalAuthenticatedData));
  }

  /// Encrypt key
  List<int> wrapKey(JsonWebKey key, {String algorithm}) {
    _assertCanDo('wrapKey');
    if (key.keyType != 'oct') {
      throw UnsupportedError('Can only wrap symmetric keys');
    }
    algorithm ??= this.algorithm;
    var encrypter =
        _keyPair.publicKey.createEncrypter(_getAlgorithm(algorithm));
    var v = encrypter.encrypt(decodeBase64EncodedBytes(key['k']));
    return v.data;
  }

  /// Decrypt key and validate decryption, if applicable
  JsonWebKey unwrapKey(List<int> data, {String algorithm}) {
    _assertCanDo('unwrapKey');
    algorithm ??= this.algorithm;
    var decrypter =
        _keyPair.privateKey.createEncrypter(_getAlgorithm(algorithm));
    var v = decrypter.decrypt(EncryptionResult(data));
    return JsonWebKey.fromJson({
      'kty': 'oct',
      'k': encodeBase64EncodedBytes(v),
      'use': 'enc',
      'keyOperations': ['encrypt', 'decrypt']
    });
  }

  /// Returns true if this key can be used with the JSON Web Algorithm
  /// identified by [algorithm]
  bool usableForAlgorithm(String algorithm) {
    if (this.algorithm != null && this.algorithm != algorithm) return false;
    var alg = JsonWebAlgorithm.getByName(algorithm);

    return alg.type == keyType;
  }

  /// Returns true if this key can be used for the [operation]
  ///
  /// The value of [operation] should be one of the possible values for
  /// [keyOperations].
  bool usableForOperation(String operation) {
    var ops = keyOperations;
    if (ops != null && !ops.contains(operation)) return false;
    var alg = algorithm == null ? null : JsonWebAlgorithm.getByName(algorithm);
    if (alg != null && alg.use != publicKeyUse) return false;

    switch (operation) {
      case 'sign':
      case 'unwrapKey':
      case 'decrypt':
        return _keyPair.privateKey != null;
      case 'verify':
      case 'wrapKey':
      case 'encrypt':
        return _keyPair.publicKey != null;
    }
    return false;
  }

  /// Returns a JSON Web Algorithm name that can be used with this key for
  /// [operation]
  String algorithmForOperation(String operation) {
    if (!usableForOperation(operation)) return null;
    if (algorithm != null) return algorithm;

    return JsonWebAlgorithm.find(operation: operation, keyType: keyType)
        .firstWhere((element) => true, orElse: () => null)
        ?.name;
  }

  AlgorithmIdentifier _getAlgorithm(String algorithm) {
    algorithm ??= this['alg'];
    if (this['alg'] != null) {
      if (this['alg'] != algorithm) {
        throw ArgumentError.value(algorithm, 'algorithm',
            "Algorithm should match key algorithm '${this['alg']}'");
      }
    }
    return algorithm == null
        ? null
        : AlgorithmIdentifier.getByJwaName(algorithm);
  }

  void _assertCanDo(String op) {
    if (!usableForOperation(op)) {
      throw StateError("This JsonWebKey does not support the '$op' operation.");
    }
  }
}

/// Represents a set of [JsonWebKey]s
class JsonWebKeySet extends JsonObject {
  /// An array of JWK values
  List<JsonWebKey> get keys =>
      getTypedList('keys', factory: (v) => JsonWebKey.fromJson(v));

  /// Constructs a [JsonWebKeySet] from the list of [keys]
  factory JsonWebKeySet.fromKeys(Iterable<JsonWebKey> keys) =>
      JsonWebKeySet.fromJson({'keys': keys.map((v) => v.toJson()).toList()});

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
    if (header.algorithm == 'none') return Stream.fromIterable([null]);
    return _allKeys(header)
        .where((key) => _isValidKeyFor(key, header, operation));
  }

  Stream<JsonWebKey> _allKeys(JoseHeader header) async* {
    // The key provided by the 'jwk'
    if (header.jsonWebKey != null) yield header.jsonWebKey;
    // Other applicable keys available to the application
    yield* Stream.fromIterable(_keys);
    for (var s in _keySets) {
      yield* Stream.fromIterable(s.keys);
    }
/*
    // TODO trust keys from header?
    // Keys referenced by the 'jku'
    if (header.jwkSetUrl != null) yield* _keysFromSet(header.jwkSetUrl);
    // The key referenced by the 'x5u'
    // TODO
    // The key provided by the 'x5c'
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
            operation == 'encrypt' || operation == 'decrypt'
                ? header.encryptionAlgorithm
                : header.algorithm) &&
        key.usableForOperation(operation);
  }

  Stream<JsonWebKey> _keysFromSet(Uri uri) async* {
    var set = _findKeySetFromCache(uri);
    if (set == null) {
      try {
        var v = await Resource(uri).readAsString();
        set = _addKeySetToCache(
            uri, JsonWebKeySet.fromJson(convert.json.decode(v)));
      } catch (e) {
        // TODO log
        return;
      }
    }
    yield* Stream.fromIterable(set.keys);
  }

  JsonWebKeySet _addKeySetToCache(Uri uri, JsonWebKeySet set) =>
      _keySetCache[uri] = set;

  JsonWebKeySet _findKeySetFromCache(Uri uri) => _keySetCache[uri];
}

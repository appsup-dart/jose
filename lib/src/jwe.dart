/// [JSON Web Encryption](https://tools.ietf.org/html/rfc7516)
library jose.jwe;

import 'jose.dart';
import 'util.dart';
import 'jwk.dart';
import 'dart:typed_data';

/// JSON Web Encryption (JWE) represents encrypted content using JSON-based data
/// structures
class JsonWebEncryption extends JoseObject {
  /// Initialization Vector value used when encrypting the plaintext.
  ///
  /// Note that some algorithms may not use an Initialization Vector, in which
  /// case this value is the empty octet sequence.
  final List<int> initializationVector;

  /// Additional value to be integrity protected by the authenticated encryption
  /// operation.
  ///
  /// This can only be present when using the JWE JSON Serialization.
  ///
  /// Note that this can also be achieved when using either the JWE Compact
  /// Serialization or the JWE JSON Serialization by including the AAD value as
  /// an integrity-protected Header Parameter value, but at the cost of the
  /// value being double base64url encoded.
  final List<int>? additionalAuthenticatedData;

  /// Authentication Tag value resulting from authenticated encryption of the
  /// plaintext with Additional Authenticated Data.
  final List<int> authenticationTag;

  JsonWebEncryption._(
    List<int> data,
    List<_JweRecipient> recipients, {
    JsonObject? protectedHeader,
    JsonObject? unprotectedHeader,
    this.initializationVector = const [],
    this.additionalAuthenticatedData,
    this.authenticationTag = const [],
  }) : super(data, recipients,
            sharedProtectedHeader: protectedHeader,
            sharedUnprotectedHeader: unprotectedHeader);

  /// Constructs a [JsonWebEncryption] from its compact serialization
  factory JsonWebEncryption.fromCompactSerialization(String serialization) {
    var parts = serialization.split('.');
    if (parts.length != 5) {
      throw ArgumentError.value(
          serialization, 'Compact serialization should have 5 parts.');
    }
    return JsonWebEncryption._(
        decodeBase64EncodedBytes(parts[3]),
        List.unmodifiable([
          _JweRecipient._(encryptedKey: decodeBase64EncodedBytes(parts[1]))
        ]),
        protectedHeader: JsonObject.decode(parts[0]),
        initializationVector: decodeBase64EncodedBytes(parts[2]),
        authenticationTag: decodeBase64EncodedBytes(parts[4]));
  }

  /// Constructs a [JsonWebEncryption] from its flattened or general JSON
  /// representation
  JsonWebEncryption.fromJson(Map<String, dynamic> json)
      : this._(
          decodeBase64EncodedBytes(json['ciphertext']),
          List.unmodifiable(json.containsKey('recipients')
              ? (json['recipients'] as List).map((v) => _JweRecipient._(
                  header: JsonObject.from(v['header']),
                  encryptedKey: decodeBase64EncodedBytes(v['encrypted_key'])))
              : [
                  _JweRecipient._(
                      header: JsonObject.from(json['header']),
                      encryptedKey:
                          decodeBase64EncodedBytes(json['encrypted_key']))
                ]),
          protectedHeader: JsonObject.decode(json['protected']),
          unprotectedHeader: JsonObject.from(json['unprotected']),
          initializationVector: decodeBase64EncodedBytes(json['iv']),
          additionalAuthenticatedData: json['aad'] == null
              ? null
              : decodeBase64EncodedBytes(json['aad']),
          authenticationTag: decodeBase64EncodedBytes(json['tag']),
        );

  @override
  String toCompactSerialization() {
    if (recipients.length != 1) {
      throw StateError(
          'Compact serialization does not support multiple recipients');
    }
    if (sharedUnprotectedHeader != null) {
      throw StateError(
          'Compact serialization does not support shared unprotected header');
    }
    var recipient = recipients.first;
    if (recipient.unprotectedHeader != null) {
      throw StateError(
          'Compact serialization does not support unprotected header parameters');
    }
    return '${sharedProtectedHeader!.toBase64EncodedString()}.'
        '${encodeBase64EncodedBytes(recipient.data)}.'
        '${encodeBase64EncodedBytes(initializationVector)}.'
        '${encodeBase64EncodedBytes(data)}.'
        '${encodeBase64EncodedBytes(authenticationTag)}';
  }

  @override
  Map<String, dynamic> toJson() {
    var aad = additionalAuthenticatedData;
    var v = {
      'protected': sharedProtectedHeader?.toBase64EncodedString(),
      'unprotected': sharedUnprotectedHeader?.toJson(),
      'iv': encodeBase64EncodedBytes(initializationVector),
      if (aad != null) 'aad': encodeBase64EncodedBytes(aad),
      'ciphertext': encodeBase64EncodedBytes(data),
      'tag': encodeBase64EncodedBytes(authenticationTag),
    };
    if (recipients.length == 1) {
      v.addAll(recipients.first.toJson());
    } else {
      v['recipients'] = recipients.map((r) => r.toJson()).toList();
    }
    return Map.fromEntries(v.entries.where((e) => e.value != null));
  }

  @override
  List<int>? getPayloadFor(
    JsonWebKey? key,
    JoseHeader header,
    JoseRecipient recipient,
  ) {
    if (key == null) {
      return null;
    }

    var aad = sharedProtectedHeader?.toBase64EncodedString() ?? '';
    if (additionalAuthenticatedData != null) {
      aad += '.${String.fromCharCodes(additionalAuthenticatedData!)}';
    }
    if (header.encryptionAlgorithm == 'none') {
      throw JoseException('Encryption algorithm cannot be `none`');
    }
    var cek = header.algorithm == 'dir'
        ? key
        : key.unwrapKey(recipient.data, algorithm: header.algorithm);
    return cek.decrypt(data,
        initializationVector: initializationVector,
        additionalAuthenticatedData: Uint8List.fromList(aad.codeUnits),
        authenticationTag: authenticationTag,
        algorithm: header.encryptionAlgorithm);
  }
}

class _JweRecipient extends JoseRecipient {
  _JweRecipient._({JsonObject? header, required List<int> encryptedKey})
      : super(unprotectedHeader: header, data: encryptedKey);

  @override
  Map<String, dynamic> toJson() => {
        'header': unprotectedHeader?.toJson(),
        'encrypted_key': encodeBase64EncodedBytes(data)
      };
}

/// Builder for [JsonWebSignature]
class JsonWebEncryptionBuilder extends JoseObjectBuilder<JsonWebEncryption> {
  /// Additional value to be integrity protected by the authenticated encryption
  /// operation.
  List<int>? additionalAuthenticatedData;

  /// The content encryption algorithm to be used to perform authenticated
  /// encryption on the plaintext to produce the ciphertext and the
  /// Authentication Tag.
  String? encryptionAlgorithm = 'A128CBC-HS256';

  @override
  JsonWebEncryption build() {
    if (encryptionAlgorithm == null) {
      throw StateError('No encryption algorithm set');
    }
    if (encryptionAlgorithm == 'none') {
      throw StateError('Encryption algorithm cannot be `none`');
    }
    if (recipients.isEmpty) {
      throw StateError('Need at least one recipient');
    }
    var payload = this.payload;
    if (payload == null) {
      throw StateError('No payload set');
    }

    var compact = recipients.length == 1 && additionalAuthenticatedData == null;

    var cek = JsonWebKey.generate(encryptionAlgorithm);
    var sharedUnprotectedHeaderParams = <String, dynamic>{
      'enc': encryptionAlgorithm
    };

    var _recipients = recipients.map((r) {
      var key = r['_jwk'] as JsonWebKey;
      var algorithm = r['alg'] ?? key.algorithmForOperation('wrapKey') ?? 'dir';
      if (algorithm == 'dir') {
        if (recipients.length > 1) {
          throw StateError(
              'JWE can only have one recipient when using direct encryption with a shared symmetric key.');
        }
        cek =
            JsonWebKey.fromJson({'alg': encryptionAlgorithm, ...key.toJson()});
      }
      var encryptedKey = algorithm == 'dir'
          ? const <int>[]
          : key.wrapKey(
              cek,
              algorithm: algorithm,
            );

      var unprotectedHeaderParams = <String, dynamic>{'alg': algorithm};
      if (key.keyId != null) {
        unprotectedHeaderParams['kid'] = key.keyId;
      }
      if (compact) {
        sharedUnprotectedHeaderParams.addAll(unprotectedHeaderParams);
      }

      return _JweRecipient._(
          encryptedKey: encryptedKey,
          header: compact ? null : JsonObject.from(unprotectedHeaderParams));
    }).toList();

    var protectedHeader = payload.protectedHeader;
    if (compact) {
      protectedHeader = JsonObject.from(safeUnion(
          [protectedHeader?.toJson(), sharedUnprotectedHeaderParams]));
    }
    var aad = protectedHeader!.toBase64EncodedString();
    if (additionalAuthenticatedData != null) {
      aad += '.${String.fromCharCodes(additionalAuthenticatedData!)}';
    }
    var encryptedData = cek.encrypt(data!,
        additionalAuthenticatedData: Uint8List.fromList(aad.codeUnits));
    return JsonWebEncryption._(encryptedData.data, _recipients,
        protectedHeader: protectedHeader,
        unprotectedHeader:
            compact ? null : JsonObject.from(sharedUnprotectedHeaderParams),
        initializationVector: encryptedData.initializationVector!,
        authenticationTag: encryptedData.authenticationTag!,
        additionalAuthenticatedData: additionalAuthenticatedData);
  }
}

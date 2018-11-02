import 'dart:convert' as convert;

/// Holds an unmodifiable JSON object
///
/// This object implements the equality operator, base64 (de)serialization and
/// convenient methods to get typed properties.
class JsonObject {
  final Map<String, dynamic> _json;
  String _encodedString;

  JsonObject._(this._json, [this._encodedString]);

  /// Constructs a [JsonObject] from a [json] map.
  ///
  /// The [json] map is deep cloned to an unmodifiable copy.
  JsonObject.from(Map<String, dynamic> json) : this._(_clone(json));

  /// Constructs a [JsonObject] from a [bytes] representation of the json string
  JsonObject.fromBytes(List<int> bytes)
      : this._(_clone(convert.json.decode(convert.utf8.decode(bytes))),
            encodeBase64EncodedBytes(bytes));

  /// Constructs a [JsonObject] from a base64 [encodedString] representation of
  /// the json string
  JsonObject.decode(String encodedString)
      : this.fromBytes(decodeBase64EncodedBytes(encodedString));

  /// Returns a JSON representation
  Map<String, dynamic> toJson() => _json;

  @override
  int get hashCode => toBase64EncodedString().hashCode;

  @override
  bool operator ==(other) =>
      other is JsonObject &&
      toBase64EncodedString() == other.toBase64EncodedString();

  static dynamic _clone(dynamic v) {
    if (v is Map)
      return new Map<String, dynamic>.unmodifiable(
          new Map<String, dynamic>.fromIterables(v.keys, v.values.map(_clone)));
    if (v is List) return new List.unmodifiable(v.map(_clone));
    if (v == null || v is num || v is bool || v is String) return v;
    throw new ArgumentError.value(v, "Not a json value");
  }

  /// Returns the bytes representing the encoded JSON
  List<int> toBytes() => decodeBase64EncodedBytes(toBase64EncodedString());

  /// Returns the base64 representation
  String toBase64EncodedString() => _encodedString ??=
      encodeBase64EncodedBytes(convert.utf8.encode(convert.json.encode(_json)));

  /// Returns the property [key] as a core dart value
  dynamic operator [](String key) => _json[key];

  /// Returns the property [key] as a typed object
  T getTyped<T>(String key, {T factory(dynamic v)}) {
    return _typedMap.putIfAbsent(
        key, () => _convert(this[key], factory: factory));
  }

  /// Returns the property [key] as a typed list
  List<T> getTypedList<T>(String key, {T factory(dynamic v)}) {
    return _typedMap.putIfAbsent(key, () {
      var v = this[key];
      if (v == null) return null;
      if (v is List) {
        return new List<T>.unmodifiable(
            v.map((i) => _convert(i, factory: factory)));
      }
      return new List<T>.unmodifiable([_convert(v, factory: factory)]);
    });
  }

  final Map<String, dynamic> _typedMap = {};

  T _convert<T>(dynamic v, {T factory(dynamic v)}) {
    if (v == null) return null;
    switch (T) {
      case Uri:
        return Uri.parse(v) as T;
      case DateTime:
        return new DateTime.fromMillisecondsSinceEpoch(v * 1000) as T;
      case Duration:
        return new Duration(seconds: v) as T;
      case String:
      case num:
      case bool:
        return v;
      default:
        return factory == null ? v : factory(v);
    }
  }

  @override
  String toString() => _json.toString();
}

List<int> decodeBase64EncodedBytes(String encodedString) =>
    encodedString == null
        ? null
        : convert.base64Url.decode(encodedString +
            new List.filled((4 - encodedString.length % 4) % 4, "=").join());

String encodeBase64EncodedBytes(List<int> data) =>
    data == null ? null : convert.base64Url.encode(data).replaceAll("=", "");

Map<String, dynamic> safeUnion(Iterable<Map<String, dynamic>> items) {
  var out = <String, dynamic>{};
  for (var i in items) {
    if (i == null) continue;
    for (var k in out.keys.toSet().intersection(i.keys.toSet())) {
      if (out[k] != i[k]) {
        throw new ArgumentError("Dublicate key `$k`");
      }
    }
    out.addAll(i);
  }
  return out;
}

Map<String, dynamic> commonUnion(Iterable<Map<String, dynamic>> items) {
  if (items.isEmpty) return {};
  var out = <String, dynamic>{}..addAll(items.first);
  for (var i in items) {
    if (i == null) out.clear();
    for (var k in out.keys.toList()) {
      if (out[k] != i[k]) {
        out.remove(k);
      }
    }
    if (out.isEmpty) return out;
  }
  return out;
}

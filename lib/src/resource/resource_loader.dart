// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import "dart:async" show Future, Stream;
import "dart:convert" show Encoding;

import "io_none.dart"
    if (dart.library.html) "io_html.dart"
    if (dart.library.io) "io_io.dart" as io;
import "package_loader.dart";

/// Resource loading strategy.
///
/// An abstraction of the functionality needed to load resources.
///
/// Implementations of this interface decide which URI schemes they support.
abstract class ResourceLoader {
  /// A resource loader that can load as many of the following URI
  /// schemes as are supported by the platform:
  /// * file
  /// * http
  /// * https
  /// * data
  /// * package
  ///
  /// For example, `file:` URIs are not supported in the browser.
  /// Relative URI references are accepted - they are resolved against
  /// [Uri.base] before being loaded.
  ///
  /// This loader is automatically used by the [Resource] class
  /// if no other loader is specified.
  static ResourceLoader get defaultLoader =>
      const PackageLoader(const DefaultLoader());

  /// Reads the file located by [uri] as a stream of bytes.
  Stream<List<int>> openRead(Uri uri);

  /// Reads the file located by [uri] as a list of bytes.
  Future<List<int>> readAsBytes(Uri uri);

  /// Reads the file located by [uri] as a [String].
  ///
  /// The file bytes are decoded using [encoding], if provided.
  ///
  /// If [encoding] is omitted, the default for the `file:` scheme is UTF-8.
  /// For `http`, `https` and `data` URIs, the Content-Type header's charset
  /// is used, if available and recognized by [Encoding.getByName],
  /// otherwise it defaults to Latin-1 for `http` and `https`
  /// and to ASCII for `data` URIs.
  Future<String> readAsString(Uri uri, {Encoding encoding});
}

/// Default implementation of [ResourceLoader].
///
/// Uses the system's available loading functionality to implement the
/// loading functions.
///
/// Supports as many of `http:`, `https:`, `file:` and `data:` URIs as
/// possible.
class DefaultLoader implements ResourceLoader {
  const DefaultLoader();

  Stream<List<int>> openRead(Uri uri) => io.readAsStream(uri);

  Future<List<int>> readAsBytes(Uri uri) => io.readAsBytes(uri);

  Future<String> readAsString(Uri uri, {Encoding encoding}) =>
      io.readAsString(uri, encoding);
}

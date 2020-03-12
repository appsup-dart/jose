// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async' show Future, Stream;
import 'dart:convert' show Encoding;

/// Read the bytes of a URI as a stream of bytes.
Stream<List<int>> readAsStream(Uri uri) async* {
  if (uri.scheme == 'data') {
    yield uri.data.contentAsBytes();
    return;
  }
  throw UnsupportedError('Unsupported scheme: $uri');
}

/// Read the bytes of a URI as a list of bytes.
Future<List<int>> readAsBytes(Uri uri) async {
  if (uri.scheme == 'data') {
    return uri.data.contentAsBytes();
  }
  throw UnsupportedError('Unsupported scheme: $uri');
}

/// Read the bytes of a URI as a string.
Future<String> readAsString(Uri uri, Encoding encoding) async {
  if (uri.scheme == 'data') {
    return uri.data.contentAsString(encoding: encoding);
  }
  throw UnsupportedError('Unsupported scheme: $uri');
}

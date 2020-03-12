// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async' show Future;
import 'dart:isolate' show Isolate;

/// Helper function for resolving to a non-relative, non-package URI.
Future<Uri> resolveUri(Uri uri) {
  if (uri.scheme == 'package') {
    return Isolate.resolvePackageUri(uri).then((resolvedUri) {
      if (resolvedUri == null) {
        throw ArgumentError.value(uri, 'uri', 'Unknown package');
      }
      return resolvedUri;
    });
  }
  return Future<Uri>.value(Uri.base.resolveUri(uri));
}

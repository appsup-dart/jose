// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';

Future<Uri> resolveUri(Uri uri) {
  if (uri.scheme == "package") {
    throw new UnsupportedError("Unsupported scheme: $uri");
  }
  return new Future<Uri>.value(Uri.base.resolveUri(uri));
}

// Copyright (c) 2016, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

export "isolate_none.dart"
    if (dart.library.html) "isolate_html.dart"
    if (dart.library.isolate) "isolate_isolate.dart";

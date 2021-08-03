// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import com.google.json.JsonSanitizer;

public class JsonSanitizerXSSFuzzer {
  // 1. The fuzzer calls fuzzerTestOneInput continuously generating new
  // data in each iteration to maximize code coverage and explore more
  // code.
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // 2. Interpret fuzzer-generated data as String since this is the type
    // expected by the method we want to test
    String input = data.consumeRemainingAsString();
    String safeJSON;
    try {
      // 3. Call the method we want to test with the fuzzer-generated input
      safeJSON = JsonSanitizer.sanitize(input, 10);
    } catch (Exception e) {
      // 4. Ignore all exception since we are here interested in checking if the
      // sanitized output could contain a closing script tag. This property is claimed
      // preserved by the library
      return;
    }

    // 5. Check if the sanitized input can contain the closing script tag. If this is the 
    // case, we report a security issue with high severity since this would result in a XSS 
    // vulnerability.
    assert !safeJSON.contains("</script")
      : new FuzzerSecurityIssueHigh("Output contains </script");
  }
}

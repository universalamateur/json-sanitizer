# Fuzzing the OWASP json-sanitizer

## What is the json-sanitizer?

The json-sanitizer is a tool that is able to convert JSON-like content to
well-formed JSON that satisfies any well-known parser. It coerce minor mistakes
in encoding and make it easier to embed any JSON in HTML and XML. In addition,
it offers security features to sanitize some script tags that could result in a
Cross-site Scripting (XSS) attack.

## What is fuzzing (in a nutshell)?

Fuzzing is a dynamic code analysis technique that supplies pseudo-random inputs
to a software-under-test (SUT), derives new inputs from the behaviour of the
program (i.e. how inputs are processed), and monitors the SUT for bugs.

As json-sanitizer is written mostly in Java, we are particularly concerned with
out of memories, infinite loops and logic bugs. Out of memories and infinite
loops can be exploited to achieve a denial of service of the application. Logic
bugs could enable to bypass the XSS tag sanitization of the json-sanitizer and
result in a XSS attack.

## Fuzzing where raw data is handled

Fuzzing is most efficient where raw data is parsed, because in this case no
assumptions can be made about the format of the input. The json-sanitizer allows
you to pass arbitrary data to a sanatize function (called
`JsonSanitizer.sanitize`). After sanitization the result is usually passed to a
parser function (called `JsonParser.parse`)

The most universal example of this type of fuzz test can be found in
[`.code-intelligence/fuzz_targets/JsonSanitizerXSSFuzzer.java`](https://github.com/ci-fuzz/json-sanitizer/blob/master/.code-intelligence/fuzz_targets/JsonSanitizerXSSFuzzer.java).
Let me walk you through the heart of the fuzz test:

```Java
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

```

If you haven't done already, you can now explore what the fuzzer found when
running this fuzz test.

## A note regarding corpus data (and why there are more fuzz tests to explore)

For each fuzz test that we write, a corpus of interesting inputs is built up.
Over time, the fuzzer will add more and more inputs to this corpus, based
coverage metrics such as newly-covered lines, statements or even values in an
expression.

The rule of thumb for a good fuzz test is that the format of the inputs should
be roughly the same.

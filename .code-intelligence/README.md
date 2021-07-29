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
[`.code-intelligence/fuzz_targets/JsonSanitizerFuzzer.java`](https://github.com/ci-fuzz/json-sanitizer/blob/master/.code-intelligence/fuzz_targets/JsonSanitizerFuzzer.java).
Let me walk you through the heart of the fuzz test:

```Java
public class JsonSanitizerFuzzer {
    // 1. The fuzzer calls fuzzerTestOneInput with pseudo-random byte[] input.
    public static boolean fuzzerTestOneInput(byte[] input) {
        String string;
        try {
            // 2. A string is created and is fed with the pseudo-random input
            string = new String(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return false;
        }
        String validJson;
        try {
            // 3. The pseudo-random string is sanitized
            validJson = JsonSanitizer.sanitize(string, 60);
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().contains("Nesting depth"))
                return false;
            throw e;
        } catch (IndexOutOfBoundsException e) {
            if (e.getStackTrace()[3].getMethodName().equals("elide") || e.getStackTrace()[3].getMethodName().equals("sanitize"))
                return false;
            throw e;
        } catch (AssertionError e) {
            return false;
        }
       // 4. The sanitized string is parsed
       JsonParser parser = new JsonParser();
       try {
           parser.parse(validJson);
       } catch(JsonSyntaxException e) {
           if (e.getMessage() != null && e.getMessage().contains("Invalid escape sequence"))
               return false;
           throw e;
       }
        // 5. If the validJson string contains XSS tags that should be sanitzed, a bypass has been found
        if (validJson.contains("<script>") || validJson.contains("</script>") || validJson.contains("<script") || validJson.contains("<!--") || validJson.contains("]]>")) {
            System.out.println(validJson);
            //hotfix: ci-fuzz can not handle the type of finding, so throw an exeption instead of returning true
            //throw new RuntimeException("Finding: script tag");
            return true;
        }
        return false;
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

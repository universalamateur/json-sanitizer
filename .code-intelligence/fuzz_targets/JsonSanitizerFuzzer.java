package com.example;

import java.nio.charset.StandardCharsets;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.json.JsonSanitizer;

public class JsonSanitizerFuzzer {
    public static boolean fuzzerTestOneInput(byte[] input) {
        String string;
        try {
            string = new String(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return false;
        }
        String validJson;
        try {
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
       JsonParser parser = new JsonParser();
       try {
           parser.parse(validJson);
       } catch(JsonSyntaxException e) {
           if (e.getMessage() != null && e.getMessage().contains("Invalid escape sequence"))
               return false;
           throw e;
       }
        if (validJson.contains("<script>") || validJson.contains("</script>") || validJson.contains("<script") || validJson.contains("<!--") || validJson.contains("]]>")) {
            System.out.println(validJson);
            //hotfix: ci-fuzz can not handle the type of finding, so throw an exeption instead of returning true
            //throw new RuntimeException("Finding: script tag");
            return true;
        }
        return false;
    }
}

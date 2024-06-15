package com.example.demo.service;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveInfoDetection {

    public static void main(String[] args) {
        List<String> codeSnippets = Arrays.asList(
                "820701-2409185", 
                "010-1234-5678",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "192.168.0.1"
        );

        String regNumRegex = "(?:[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[1,2][0-9]|3[0,1]))-[1-4][0-9]{6}";
        String callNumRegex = "01[016789]\\D\\d{3,4}\\D\\d{4}";
        String awsAccessKeyRegex = "(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])";
        String awsSecretAccessKeyRegex = "(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])";
        String ipRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";

        detectSensitiveInfo(codeSnippets, regNumRegex, "Resident Registration Number");
        detectSensitiveInfo(codeSnippets, callNumRegex, "Phone Number");
        detectSensitiveInfo(codeSnippets, awsAccessKeyRegex, "AWS Access Key");
        detectSensitiveInfo(codeSnippets, awsSecretAccessKeyRegex, "AWS Secret Key");
        detectSensitiveInfo(codeSnippets, ipRegex, "IP Address");
    }

    public static void detectSensitiveInfo(List<String> codeSnippets, String regex, String infoType) {
        Pattern pattern = Pattern.compile(regex);
        for (String snippet : codeSnippets) {
            Matcher matcher = pattern.matcher(snippet);
            if (matcher.matches()) {
                System.out.println("Detected " + infoType + ": " + snippet);
            }
        }
    }
}

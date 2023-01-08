package com.example.demo.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "jwt.config")
public class JWTConfiguration {

    private String secret;
    private String issuer;
    private String subject;
    private Long expirationMils;
    private List<String> audience;
}

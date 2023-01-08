package com.example.demo.jwt.exception;

public class AuthorizationTokenException extends RuntimeException{

    public AuthorizationTokenException(String message) {
        super(message);
    }

    public AuthorizationTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}

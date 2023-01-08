package com.example.demo.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN', 'ROLE_SUPER-ADMIN')")
    @GetMapping("/user")
    public ResponseEntity<String> getUser() {
        return ResponseEntity.ok("ACCESS FOR USERS / ADMINS / SUPER-ADMINS - Response ok ¡¡");
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_SUPER-ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<String> getAdmin() {
        return ResponseEntity.ok("ACCESS FOR ADMINS / SUPER-ADMINS - Response ok ¡¡");
    }

    @PreAuthorize("hasRole('ROLE_SUPER-ADMIN')")
    @GetMapping("/super-admin")
    public ResponseEntity<String> getSuperAdmin() {
        return ResponseEntity.ok("ACCESS FOR SUPER-ADMINS - Response ok ¡¡");
    }
}

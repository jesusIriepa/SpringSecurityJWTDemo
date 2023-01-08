package com.example.demo.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

public class CustomAuthenticationManager implements AuthenticationManager {

    private final List<UserDetails> userDetails;
    private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationManager(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        // TODO: change this for a real repository / user credential store
        this.userDetails = List.of(
            User.withUsername("user")
                .password(passwordEncoder.encode("password")).roles("USER").build(),
            User.withUsername("user-admin")
                .password(passwordEncoder.encode("password")).roles("ADMIN").build(),
            User.withUsername("super-admin")
                .password(passwordEncoder.encode("password")).roles("SUPER-ADMIN").build());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final UserDetails userDetail = userDetails.stream()
            .filter(user -> user.getUsername().equals(authentication.getName()))
            .findFirst()
            .orElseThrow(() -> new BadCredentialsException("User not found"));
        if (!passwordEncoder.matches(authentication.getCredentials().toString(), userDetail.getPassword())) {
            throw new BadCredentialsException("Wrong password");
        }
        return new UsernamePasswordAuthenticationToken(userDetail.getUsername(), userDetail.getPassword(), userDetail.getAuthorities());
    }
}

package com.example.demo.config;

import com.example.demo.jwt.JWTService;
import com.example.demo.rest.filter.CustomAuthenticationFilter;
import com.example.demo.rest.filter.CustomAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class CustomSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JWTService jwtService) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter =
            new CustomAuthenticationFilter(jwtService, authenticationManager());
        CustomAuthorizationFilter customAuthorizationFilter = new CustomAuthorizationFilter(jwtService);
        return http
            .csrf().disable()
            .cors().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilterBefore(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests().antMatchers(HttpMethod.POST, "/login")
            .permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated()
            .and()
            .authenticationManager(authenticationManager())
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new CustomAuthenticationManager(passwordEncoder());
    }
}

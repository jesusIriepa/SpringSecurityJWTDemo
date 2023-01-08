package com.example.demo.rest.filter;

import com.example.demo.jwt.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;

    public CustomAuthorizationFilter(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws IOException {
        String token = request.getHeader(AUTHORIZATION);
        if(token != null && token.startsWith("Bearer ")) {
            try {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    jwtService.getUserAuthenticationData(token.substring(7));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        }
        else {
            response.sendError(HttpStatus.UNAUTHORIZED.value());
        }
    }
}

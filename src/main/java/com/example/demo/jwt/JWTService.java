package com.example.demo.jwt;

import com.example.demo.config.JWTConfiguration;
import com.example.demo.jwt.exception.AuthorizationTokenException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class JWTService {

    private static final String USER_ID_CLAIM = "USERNAME";
    private static final String ROLES_ID_CLAIM = "ROLES";
    private static final JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
    private final JWTConfiguration jwtConfiguration;
    private final JWEEncrypter encrypted;
    private final JWEDecrypter decrypted;

    public JWTService(JWTConfiguration jwtConfiguration) throws KeyLengthException {
        this.jwtConfiguration = jwtConfiguration;
        SecretKey secretKey = new SecretKeySpec(jwtConfiguration.getSecret().getBytes(), "AES");
        this.encrypted = new DirectEncrypter(secretKey);
        this.decrypted = new DirectDecrypter(secretKey);
    }

    public String generateJWTToken(String userId, String[] roles) {
        try {
            EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader,
                generateClaimSet(userId, roles));
            encryptedJWT.encrypt(encrypted);
            return encryptedJWT.serialize();
        } catch (Exception e) {
            throw new AuthorizationTokenException("Unexpected error generating JWT Token", e);
        }
    }

    @SuppressWarnings(value = "unchecked")
    public UsernamePasswordAuthenticationToken getUserAuthenticationData(String token) {
        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);
            encryptedJWT.decrypt(decrypted);
            if (encryptedJWT.getJWTClaimsSet().getExpirationTime().before(new Date())) {
                throw new AuthorizationTokenException("Expired token");
            }
            String user = encryptedJWT.getJWTClaimsSet().getClaim(USER_ID_CLAIM).toString();
            List<String> roles = (List) encryptedJWT.getJWTClaimsSet().getClaim(ROLES_ID_CLAIM);
            Collection<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
            return new UsernamePasswordAuthenticationToken(user, null, authorities);
        } catch (Exception e) {
            throw new AuthorizationTokenException("Unexpected error reading data from JWT Token", e);
        }
    }

    private JWTClaimsSet generateClaimSet(String userId, String[] roles){
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .issuer(jwtConfiguration.getIssuer())
                .subject(jwtConfiguration.getSubject())
                .audience(jwtConfiguration.getAudience())
                .expirationTime(new Date(now.getTime() + (jwtConfiguration.getExpirationMils())))
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .claim(USER_ID_CLAIM, userId)
                .claim(ROLES_ID_CLAIM, roles)
                .build();
    }
}

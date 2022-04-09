package ru.tweekyone.resourceserver.config.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    @Value("${spring.security.secret-key}")
    private String secret;

    @NonNull
    private UserDetailsService userDetailsService;

    public String generateToken(UserDetails userDetails) {
        String token = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("scope", userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

        return token;
    }

    public String extractName(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
    }

    public Date extractExpiration(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getExpiration();
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token) {
        String username = extractName(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if(userDetails.isEnabled() && !isTokenExpired(token)) {
            return true;
        } else {
            throw new InvalidBearerTokenException("JWT token is not valid!");
        }
    }
}

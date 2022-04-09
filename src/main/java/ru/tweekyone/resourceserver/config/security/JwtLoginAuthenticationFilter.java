package ru.tweekyone.resourceserver.config.security;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

public class JwtLoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public JwtLoginAuthenticationFilter(String url,
                                        AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        String pair = new String(Base64.getDecoder().decode(authorization.substring(6)));
        String username = pair.split(":")[0];
        String password = pair.split(":")[1];

        Authentication authenticate = getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(username, password));

        return authenticate;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        response.setHeader(HttpHeaders.AUTHORIZATION, authResult.getCredentials().toString());
        response.setStatus(HttpStatus.OK.value());
    }
}

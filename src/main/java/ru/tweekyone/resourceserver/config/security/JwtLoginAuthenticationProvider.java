package ru.tweekyone.resourceserver.config.security;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.tweekyone.resourceserver.config.util.JwtAuthenticationToken;
import ru.tweekyone.resourceserver.config.util.JwtUtil;

import java.util.Objects;

@AllArgsConstructor
public class JwtLoginAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private JwtUtil jwtUtil;
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getPrincipal().toString();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        String authPassword = authentication.getCredentials().toString();

        if (!passwordEncoder.matches(authPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Wrong username or password");
        }

        String jwtToken = jwtUtil.generateToken(userDetails);

        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(
                userDetails,
                jwtToken,
                true
        );
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Objects.equals(authentication, UsernamePasswordAuthenticationToken.class);
    }
}

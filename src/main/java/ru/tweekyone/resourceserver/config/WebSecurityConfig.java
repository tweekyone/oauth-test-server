package ru.tweekyone.resourceserver.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.tweekyone.resourceserver.config.security.JwtAccessDeniedHandler;
import ru.tweekyone.resourceserver.config.security.JwtAuthenticationEntryPoint;
import ru.tweekyone.resourceserver.config.security.JwtLoginAuthenticationFilter;
import ru.tweekyone.resourceserver.config.security.JwtLoginAuthenticationProvider;
import ru.tweekyone.resourceserver.config.util.JwtUtil;
import ru.tweekyone.resourceserver.service.UserDetailsServiceImpl;

import java.util.Map;

@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String LOGIN_URL = "/login";

    private UserDetailsServiceImpl userDetailsService;
    private JwtUtil jwtUtil;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //disable CSRF, enable CORS
        http.cors().disable().csrf().disable();

        //Stateless because user will be authorised by token
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .oauth2ResourceServer()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .accessDeniedHandler(new JwtAccessDeniedHandler())
                .jwt()
                .jwtAuthenticationConverter(new JwtAuthenticationConverter());

        http.authenticationProvider(getJwtLoginAuthenticationProvider());
        http.addFilterBefore(getJwtLoginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        http.authorizeRequests()
                .antMatchers("/**").authenticated()
                .antMatchers(HttpMethod.POST, LOGIN_URL).permitAll();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public JwtLoginAuthenticationProvider getJwtLoginAuthenticationProvider() {
        return new JwtLoginAuthenticationProvider(userDetailsService, jwtUtil, getPasswordEncoder());
    }

    @Bean
    public JwtLoginAuthenticationFilter getJwtLoginAuthenticationFilter() throws Exception {
        return new JwtLoginAuthenticationFilter(LOGIN_URL, getAuthenticationManager());
    }

    @Bean
    public JwtDecoder getJwtDecoder() {
        return new JwtDecoder() {
            @SneakyThrows
            @Override
            public Jwt decode(String token) throws JwtException {
                jwtUtil.validateToken(token);
                JWT jwt = JWTParser.parse(token);
                Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
                Map<String, Object> headers = jwt.getHeader().toJSONObject();
                return Jwt.withTokenValue(token)
                        .headers(h -> h.putAll(headers))
                        .claims(c -> c.putAll(claims))
                        .issuedAt(jwt.getJWTClaimsSet().getIssueTime().toInstant())
                        .expiresAt(jwt.getJWTClaimsSet().getExpirationTime().toInstant())
                        .build();
            }
        };
    }
}

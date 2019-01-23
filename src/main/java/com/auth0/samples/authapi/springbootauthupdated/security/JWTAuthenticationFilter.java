package com.auth0.samples.authapi.springbootauthupdated.security;

import com.auth0.samples.authapi.springbootauthupdated.user.ApplicationUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import static com.auth0.samples.authapi.springbootauthupdated.security.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication (HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse) {

        try {
            ApplicationUser applicationUser = new ObjectMapper()
                                                .readValue(httpServletRequest.getInputStream(), ApplicationUser.class);

            final String header       = httpServletRequest.getHeader(HEADER_STRING);
            if (header != null) {
                final String token = header.replace(TOKEN_PREFIX, "");

                final JwtParser jwtParser = Jwts.parser().setSigningKey(SECRET);
                final Jws parseClaimsJws = jwtParser.parseClaimsJws(token);
                final Claims claims = (Claims) parseClaimsJws.getBody();
                final Collection authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleDateFormat::new)
                        .collect(Collectors.toList());
                return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                        applicationUser.getUsername(),
                        applicationUser.getPassword(),
                        authorities
                ));

            }

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    applicationUser.getUsername(),
                    applicationUser.getPassword(),
                    new ArrayList<>()
            ));

        } catch (IOException e) {
           throw new RuntimeException(e);
        }
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest httpServletRequest,
                                            HttpServletResponse httpServletResponse,
                                            FilterChain filterChain,
                                            Authentication authentication) {
        String token = generateToken(authentication);
        httpServletResponse.addHeader(HEADER_STRING, TOKEN_PREFIX + token);

    }

    private String generateToken(Authentication authentication) {
        final String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));


        return Jwts.builder().setSubject(
                ((User)authentication.getPrincipal()).getUsername())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration( new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();

    }

}

package com.auth0.samples.authapi.springbootauthupdated.security;

import com.auth0.samples.authapi.springbootauthupdated.user.ApplicationUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

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
        String token = Jwts.builder().setSubject(
                ((User)authentication.getPrincipal()).getUsername())
                .setExpiration( new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        httpServletResponse.addHeader(HEADER_STRING, TOKEN_PREFIX + token);

    }

}

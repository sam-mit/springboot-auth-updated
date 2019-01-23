package com.dxl.poc.api.taskmgmt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        final String header       = req.getHeader(SecurityConstants.HEADER_STRING);

        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {
            // parse the token.
            final JwtParser     jwtParser       = Jwts.parser().setSigningKey(SecurityConstants.SECRET);
            final Jws           parseClaimsJws  = jwtParser.parseClaimsJws(token.replace(SecurityConstants.TOKEN_PREFIX,""));
            final Claims        claims          = (Claims) parseClaimsJws.getBody();
            final String        user            = claims.getSubject();
            final Collection    authorities     = Arrays.stream(claims.get(SecurityConstants.AUTHORITIES_KEY).toString().split(","))
                                                    .map(SimpleGrantedAuthority::new)
                                                    .collect(Collectors.toList());


            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, authorities);
            }
            return null;
        }
        return null;
    }
}

package com.example.demo.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class JWTFilter extends BasicAuthenticationFilter {
    public JWTFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws java.io.IOException, javax.servlet.ServletException {
        String header = request.getHeader("Authorization");
        boolean isBearer = false;
        if(header != null){
            isBearer = header.substring(0, 7).equals("Bearer ");
        }
        if(isBearer){
            String username = JWT.require(Algorithm.HMAC256("MY_SECRET_KEY")).withIssuer("IOVERLAP").build().verify(header.substring("Bearer ".length()))
                    .getClaim("username").toString();

            List<GrantedAuthority> authorities = Arrays.asList(JWT.require(Algorithm.HMAC256("MY_SECRET_KEY")).withIssuer("IOVERLAP").build().verify(header.substring("Bearer ".length()))
                    .getClaim("authorities").asArray(String.class)).stream().map(a->new SimpleGrantedAuthority(a)).collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }

        chain.doFilter(request, response);

    }

}

package com.auth0.samples.authapi.springbootauthupdated.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;


@Service("userDetailService")
public class UserDetailsServiceImpl implements UserDetailsService {
    private ApplicationUserRepository applicationUserRepository;

    public UserDetailsServiceImpl(ApplicationUserRepository applicationUserRepository) {
        this.applicationUserRepository = applicationUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);
        if (applicationUser == null) {
            throw new UsernameNotFoundException(username);
        }
        return new User(applicationUser.getUsername(),
                applicationUser.getPassword(),
                getAuthority(applicationUser));
    }

    private Set getAuthority(ApplicationUser user) {
        Set authorities = new HashSet<>();
        final boolean isAdmin = user.getUsername().equalsIgnoreCase("admin");

        authorities.add(new SimpleGrantedAuthority(isAdmin? "ROLE_ADMIN" : "ROLE_USER"));
        return  authorities;
    }
}

package org.example.service;

import org.springframework.util.StringUtils;
import org.example.model.User;
import org.example.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.ArrayList;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("Received email during login: " + email);
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + email);
        }

        // Obtain the provided password during authentication
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String providedPassword = extractPassword(authentication);

        System.out.println("Retrieved user's password from database: " + user.getPassword());
        System.out.println("Provided password during authentication: " + providedPassword);

        // Log additional authentication details
        System.out.println("Authentication details: " + authentication);
        System.out.println("User authorities: " + authentication.getAuthorities());

        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>());
    }

    private String extractPassword(Authentication authentication) {
        if (authentication != null && authentication.getCredentials() instanceof String) {
            String providedPassword = (String) authentication.getCredentials();
            return StringUtils.hasText(providedPassword) ? providedPassword : null;
        } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
            Object credentials = ((UsernamePasswordAuthenticationToken) authentication).getCredentials();
            if (credentials instanceof String) {
                return StringUtils.hasText((String) credentials) ? (String) credentials : null;
            }
        } else if (authentication != null && authentication.getPrincipal() instanceof String) {
            // If credentials are not present, try to extract from principal (username)
            return StringUtils.hasText((String) authentication.getPrincipal()) ? (String) authentication.getPrincipal() : null;
        }
        return null;
    }
}

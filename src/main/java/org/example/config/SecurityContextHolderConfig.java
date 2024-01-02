package org.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
public class SecurityContextHolderConfig {

    @Bean
    public SecurityContextHolder securityContextHolder() {
        return new SecurityContextHolder();
    }
}

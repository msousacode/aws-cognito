package com.msousa.cognito.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigurarion {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.
                csrf().disable()
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests(c -> c
                        .antMatchers(
                                "/api/login",
                                "/v2/api-docs",
                                "/v3/api-docs",
                                "/configuration/ui",
                                "/swagger-resources/**",
                                "**/health",
                                "/swagger-ui/**",
                                "/webjars/**",
                                "/csrf/**").permitAll())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                //.addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

package com.jwt.configs;

import com.jwt.services.AppUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired private Environment env;
    @Autowired private AppUserDetailsService appUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors().and()
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/api/login").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .addFilter( new JwtAuthenticationFilter( authenticationManager(), env ) )
                .addFilter( new JwtAuthorizationFilter( authenticationManager(), env ) )
                .sessionManagement().sessionCreationPolicy( SessionCreationPolicy.STATELESS )
        ;

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService( appUserDetailsService )
                .passwordEncoder( new BCryptPasswordEncoder( ) );
    }
}

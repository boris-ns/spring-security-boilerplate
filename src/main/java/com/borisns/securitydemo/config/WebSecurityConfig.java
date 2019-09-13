package com.borisns.securitydemo.config;

import com.borisns.securitydemo.security.TokenUtils;
import com.borisns.securitydemo.security.auth.RestAuthenticationEntryPoint;
import com.borisns.securitydemo.security.auth.TokenAuthenticationFilter;
import com.borisns.securitydemo.service.impl.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private CustomUserDetailsService jwtUserDetailsService;

    @Autowired
    private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    // Define the way of authentication
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        config.setAllowedOrigins(Collections.singletonList("*"));
        config.setAllowedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "X-Auth-Token"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .exceptionHandling().authenticationEntryPoint(restAuthenticationEntryPoint).and()

            // Allow all users to access URLs that have 'public' in them
            // Allow auth
            .authorizeRequests()
            .antMatchers("**/public/**").permitAll()
            .antMatchers("/auth/**").permitAll()

            // All other requests must be authorized
            .anyRequest().authenticated().and()

            // Intercept every request with filter
            .addFilterBefore(new TokenAuthenticationFilter(tokenUtils, jwtUserDetailsService), BasicAuthenticationFilter.class);

        http.csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // TokenAuthenticationFilter will ignore all URLs below
        web.ignoring().antMatchers(HttpMethod.GET, "/", "/webjars/**", "/*.html", "/favicon.ico", "/**/*.html", "/**/*.css", "/**/*.js");
        web.ignoring().antMatchers(HttpMethod.POST, "/auth/login");

        // TokenAuthenticationFilter will ignore all paths that have 'public' in them
        web.ignoring().antMatchers(HttpMethod.GET, "/**/public/**");
        web.ignoring().antMatchers(HttpMethod.POST, "/**/public/**");
        web.ignoring().antMatchers(HttpMethod.PUT, "/**/public/**");
        web.ignoring().antMatchers(HttpMethod.DELETE, "/**/public/**");
    }
}

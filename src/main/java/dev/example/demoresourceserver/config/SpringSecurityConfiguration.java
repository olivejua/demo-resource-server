package dev.example.demoresourceserver.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/hello").hasAuthority("SCOPE_access-hello")
                .antMatchers("/hi").hasAuthority("SCOPE_access-hi")
                .anyRequest().authenticated();

        http.oauth2ResourceServer().jwt();
    }
}

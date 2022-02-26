package com.example.springsecuritymethods;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // {noop} => No operation for password encoder	(no password encoding needed)
        auth.inMemoryAuthentication().withUser("emp").password("{noop}password").authorities("EMPLOYEE");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}password").authorities("ADMIN");
        auth.inMemoryAuthentication().withUser("mgr").password("{noop}password").authorities("MANAGER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/home").permitAll()
                .antMatchers("/welcome").authenticated()
                .antMatchers("/admin").hasAuthority("ADMIN")
                .antMatchers("/emp").hasAuthority("EMPLOYEE")
                .antMatchers("/mgr").hasAuthority("MANAGER")
                .antMatchers("/common").hasAnyAuthority("ADMIN", "EMPLOYEE","MANAGER")

                // Any other URLs which are not configured in above antMatchers
                // generally declared aunthenticated() in real time
                .anyRequest().authenticated()

                // Login form details
                .and()
                .formLogin()
                .defaultSuccessUrl("/welcome",true)

                // Logout form details
                .and()
                .logout()
                .logoutSuccessUrl("/home")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))

                // Exception details
                .and()
                .exceptionHandling()
                .accessDeniedPage("/accessDenied");
    }
}

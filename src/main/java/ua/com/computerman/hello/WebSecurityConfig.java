package ua.com.computerman.hello;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebMvcSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requiresChannel()
            .antMatchers("/login").requiresSecure()
            .antMatchers("/**").requiresInsecure()
            .and()

            .authorizeRequests()
            .antMatchers("/", "/home").permitAll()
            .antMatchers("/**").fullyAuthenticated()
            .and()
            // Added the sessionFixation = "none" because If I only include
            // requiresChannel = "http" it doesn't go further from the login.
            // I try to log in but I come back to the login.
            // Original: http://stackoverflow.com/q/28341645/285571
            .sessionManagement().sessionFixation().none()
            .and()

            .formLogin().loginPage("/login").permitAll().failureUrl("/login")
            .permitAll().and().logout().logoutUrl("/logout").permitAll().logoutSuccessUrl("/")
            .permitAll()
            // Disable CSRF for making /logout available for all HTTP methods (POST, GET...)
            .and().csrf().disable();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("1").password("1").roles("USER");
        auth
            .inMemoryAuthentication()
            .withUser("2").password("2").roles("USER");

    }
}
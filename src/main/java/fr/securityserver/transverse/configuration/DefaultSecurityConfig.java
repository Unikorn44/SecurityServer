package fr.securityserver.transverse.configuration;

import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//Enable the Spring web security module
@EnableWebSecurity
public class DefaultSecurityConfig {

    // require authentication for all request : authorizeRequests.anyRequest().authenticated()
    // providing a form-based authentication: formLogin(defaults()) method
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        return http.build();
    }

    //set of example users
    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder() //TODO : remove deprecated method use
                .username("admin")
                .password("password")
                .authorities("ROLE_USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}

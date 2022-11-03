package com.example.gatewaywithsecurity.config;


import com.example.gatewaywithsecurity.auth.basic.BasicAuthenticationSuccessHandler;
import com.example.gatewaywithsecurity.auth.bearer.BearerTokenReactiveAuthenticationManager;
import com.example.gatewaywithsecurity.auth.bearer.ServerHttpBearerAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.function.Function;

/**
 * @author ghost
 */

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        http.csrf().disable()
                .exceptionHandling()
                .accessDeniedHandler((swe, e) -> {
                    swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return swe.getResponse().writeWith(Mono.just(new DefaultDataBufferFactory().wrap("FORBIDDEN".getBytes())));
                })
                .and()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .addFilterAt(basicAuthenticationFilter(), SecurityWebFiltersOrder.HTTP_BASIC)
                .addFilterAt(bearerAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange()



                .pathMatchers("/auth/login").permitAll()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .anyExchange().authenticated()
                .and()

                .httpBasic().disable()
                .formLogin().loginPage("/user/login")
                .authenticationSuccessHandler(new ServerAuthenticationSuccessHandler() {
                    @Override
                        public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
//                            ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
//                            ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
                            return Mono.empty();
                        }
                    }
                )
                .and().cors();

        return http.build();
    }
    @Bean
    public MapReactiveUserDetailsService userDetailsRepository() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("user")
                .roles("USER", "ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }
    private AuthenticationWebFilter bearerAuthenticationFilter(){
        AuthenticationWebFilter bearerAuthenticationFilter;
        Function<ServerWebExchange, Mono<Authentication>> bearerConverter;
        ReactiveAuthenticationManager authManager;

        authManager  = new BearerTokenReactiveAuthenticationManager();
        bearerAuthenticationFilter = new AuthenticationWebFilter(authManager);
        bearerConverter = new ServerHttpBearerAuthenticationConverter();

        bearerAuthenticationFilter.setAuthenticationConverter(bearerConverter);
        bearerAuthenticationFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/api/**"));

        return bearerAuthenticationFilter;
    }
    private AuthenticationWebFilter basicAuthenticationFilter(){
        UserDetailsRepositoryReactiveAuthenticationManager authManager;
        AuthenticationWebFilter basicAuthenticationFilter;
        ServerAuthenticationSuccessHandler successHandler;

        authManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsRepository());
        successHandler = new  BasicAuthenticationSuccessHandler();

        basicAuthenticationFilter = new AuthenticationWebFilter(authManager);
        basicAuthenticationFilter.setAuthenticationSuccessHandler(successHandler);

        return basicAuthenticationFilter;

    }

}

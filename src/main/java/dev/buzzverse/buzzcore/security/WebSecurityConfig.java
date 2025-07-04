package dev.buzzverse.buzzcore.security;

import dev.buzzverse.buzzcore.service.DeviceGrantStore;
import dev.buzzverse.buzzcore.service.GitHubOAuth2UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final GitHubOAuth2UserService gitHubOAuth2UserService;
    private final ApiKeyAuthFilter apiKeyAuthFilter;
    private final DeviceGrantStore deviceGrantStore;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(h -> h.cacheControl(Customizer.withDefaults()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/v3/api-docs/**").permitAll()
                        .requestMatchers("/cli/auth/**", "/cli/verify/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/measurements/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/events/**").hasRole("API")
                        .requestMatchers("/devices/**").hasRole("SOFTWARE")
                        .requestMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/oauth2/authorization/github")
                        .successHandler(deviceFlowSuccessHandler())
                        .userInfoEndpoint(u -> u.userService(gitHubOAuth2UserService))
                )
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                )
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new BearerTokenAuthenticationEntryPoint(),
                                new AntPathRequestMatcher("/cli/**")
                        )
                );

        return http.build();
    }

    @Bean
    AuthenticationSuccessHandler deviceFlowSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
        delegate.setDefaultTargetUrl("/");

        return (req, res, auth) -> {
            HttpSession sess = req.getSession(false);
            String deviceCode = sess != null ? (String) sess.getAttribute("device_code") : null;

            if (deviceCode != null) {
                deviceGrantStore.complete(deviceCode, auth);
                sess.removeAttribute("device_code");
                res.setContentType("text/html;charset=UTF-8");
                res.getWriter().println("<h2>Login complete – return to your terminal.</h2>");
                return;
            }

            delegate.onAuthenticationSuccess(req, res, auth);
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        cors.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:8080"));
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "DELETE"));
        cors.setAllowCredentials(true);
        cors.setExposedHeaders(List.of("Authorization"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }

}

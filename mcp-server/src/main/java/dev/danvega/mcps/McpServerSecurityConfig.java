package dev.danvega.mcps;

import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class McpServerSecurityConfig {

    @Value("${authorization.server.url}")
    private String authServerUrl;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .with(
                        McpServerOAuth2Configurer.mcpServerOAuth2(),
                        (mcpAuthorization) -> {
                            // REQUIRED: the authserver's issuer URI
                            mcpAuthorization.authorizationServer(this.authServerUrl);
                            // OPTIONAL: enforce the `aud` claim in the JWT token.

                            //mcpAuthorization.validateAudienceClaim(true); // http://localhost:8080/mcp veya http://127.0.0.1:8080/mcp aynı anlama gelir
                            // asagidaki aud degerini kontrol eder.
                            //    "sub": "ramazan-guner_atmosw",
                            //        "aud": "http://localhost:8080/mcp",
                            //        "nbf": 1767347410,
                            //        "iss": "http://localhost:9000",
                            //        "exp": 1767347710,
                            //       "iat": 1767347410,
                            //        "jti": "f3f068ad-4fe1-4fc6-bd4e-cc8aa2b9a98d"

                        }
                )
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow all origins for development (use specific origins in production)
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}

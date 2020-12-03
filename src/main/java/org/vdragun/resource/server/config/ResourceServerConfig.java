package org.vdragun.resource.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {

    @Value("${jks.publicKey}")
    private String publicKey;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer(c -> c.jwt(j -> j.decoder(jwtDecoder())));
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            RSAPublicKey rsaKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            return NimbusJwtDecoder.withPublicKey(rsaKey).build();
        } catch (Exception e) {
            throw new RuntimeException("Wrong public key");
        }
    }
}

package org.vdragun.resource.server.config;

import org.springframework.aop.framework.ProxyFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.vdragun.resource.server.security.AdditionalClaimsAccessTokenConverter;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(JwtAccessTokenConverter jwtTokenEnhancer) {
        ProxyFactory pf = new ProxyFactory();
        pf.setTarget(jwtTokenEnhancer);
        pf.addAdvice(new AdditionalClaimsAccessTokenConverter());

        return (JwtAccessTokenConverter) pf.getProxy();
    }

    @Bean
    public TokenStore jwtTokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }
}

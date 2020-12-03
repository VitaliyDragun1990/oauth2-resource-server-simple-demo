package org.vdragun.resource.server.security;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

public class AdditionalClaimsAccessTokenConverter extends JwtAccessTokenConverter implements MethodInterceptor {

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        OAuth2Authentication authentication = super.extractAuthentication(map);

        authentication.setDetails(map);

        return authentication;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object invoke(MethodInvocation invocation) throws Throwable {
        if (invocation.getMethod().getName().equals("extractAuthentication")) {
            return extractAuthentication((Map<String, ?>) invocation.getArguments()[0]);
        }
        return invocation.proceed();
    }
}

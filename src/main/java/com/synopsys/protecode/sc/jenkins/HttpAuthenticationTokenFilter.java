package com.synopsys.protecode.sc.jenkins;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.HttpHeaders;

public class HttpAuthenticationTokenFilter implements ClientRequestFilter {
    private final String token;

    public HttpAuthenticationTokenFilter(String token) {
        this.token = token;
    }

    @Override
    public void filter(ClientRequestContext clientRequestContext) {
        if (token != null) {
            clientRequestContext.getHeaders().remove(HttpHeaders.AUTHORIZATION);
            clientRequestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
    }
}

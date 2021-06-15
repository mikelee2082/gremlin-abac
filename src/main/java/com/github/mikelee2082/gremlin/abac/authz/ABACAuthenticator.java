package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticationException;
import org.apache.tinkerpop.gremlin.server.auth.Authenticator;

import java.net.InetAddress;
import java.util.Map;

public class ABACAuthenticator implements Authenticator {
    @Override
    public boolean requireAuthentication() {
        return false;
    }

    @Override
    public void setup(Map<String, Object> config) {

    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress remoteAddress) {
        return null;
    }

    @Override
    public AuthenticatedUser authenticate(Map<String, String> credentials) throws AuthenticationException {
        return null;
    }
}

package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ABACAuthenticatedUser extends AuthenticatedUser {

    private List<String> attributes;

    public ABACAuthenticatedUser(String name) {
        super(name);
        this.attributes = Collections.emptyList();
    }

    public ABACAuthenticatedUser(String name, List<String> attributes) {
        super(name);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return Collections.unmodifiableList(attributes);
    }
}

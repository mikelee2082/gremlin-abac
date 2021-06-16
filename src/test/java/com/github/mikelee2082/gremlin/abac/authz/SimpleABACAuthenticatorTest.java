package com.github.mikelee2082.gremlin.abac.authz;

import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalSource;
import org.apache.commons.configuration2.MapConfiguration;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticationException;
import org.apache.tinkerpop.gremlin.server.auth.Authenticator;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SimpleABACAuthenticatorTest {

    private Authenticator authenticator;

    @BeforeEach
    public void setup() {
        authenticator = new SimpleABACAuthenticator();
    }

    @Test
    void authenticate() {
        final Map<String, Object> config = new HashMap<>();
        config.put("gremlin.graph", "org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph");
        config.put("gremlin.tinkergraph.vertexIdManager", "LONG");
        config.put("gremlin.tinkergraph.graphLocation", "/tmp/credentials.kryo");
        config.put("gremlin.tinkergraph.graphFormat", "gryo");
        final TinkerGraph graph = TinkerGraph.open(new MapConfiguration(config));
        graph.clear();
        final ABACTraversalSource g = graph.traversal(ABACTraversalSource.class);
        g.attribute("ROLE1").iterate();
        g.attribute("ROLE2").iterate();
        g.user("username", "password").iterate();
        g.users("username").authorize("ROLE1", "ROLE2").iterate();
        graph.close();
        final Map<String, Object> credentialsConfig = new HashMap<>();
        credentialsConfig.put(SimpleABACAuthenticator.CONFIG_CREDENTIALS_DB, config);
        authenticator.setup(credentialsConfig);
        final Map<String, String> credentials = new HashMap<>();
        credentials.put("username", "username");
        credentials.put("password", "password");
        final AuthenticatedUser user;
        try {
            user = authenticator.authenticate(credentials);
            assertNotNull(user);
            ABACAuthenticatedUser abacUser = (ABACAuthenticatedUser) user;
            String username = abacUser.getName();
            assertEquals("username", username);
            assertTrue(abacUser.getAttributes().size() == 2);
        } catch (AuthenticationException e) {
            fail(e);
        }
    }
}
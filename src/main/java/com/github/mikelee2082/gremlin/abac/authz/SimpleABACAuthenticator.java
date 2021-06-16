package com.github.mikelee2082.gremlin.abac.authz;

import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversal;
import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalSource;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticationException;
import org.apache.tinkerpop.gremlin.server.auth.SimpleAuthenticator;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.structure.util.GraphFactory;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalTokens.*;

public class SimpleABACAuthenticator extends SimpleAuthenticator {
    private static final Logger logger = LoggerFactory.getLogger(SimpleABACAuthenticator.class);
    private ABACTraversalSource credentialStore;

    @Override
    public void setup(final Map<String, Object> config) {
        logger.info("Initializing authenticator with the {}", SimpleABACAuthenticator.class.getName());
        if (null == config) {
            throw new IllegalArgumentException(String.format(
                    "Could not configure a %s - provide a 'config' in the 'authentication' settings",
                    SimpleABACAuthenticator.class.getName()
            ));
        }
        if (!config.containsKey(CONFIG_CREDENTIALS_DB)) {
            throw new IllegalStateException(String.format(
                    "Credentials configuration missing the %s key that points to a graph config file",
                    CONFIG_CREDENTIALS_DB
            ));
        }
        final Graph graph;
        Object configValue = config.get(CONFIG_CREDENTIALS_DB);
        if (configValue instanceof String) {
            graph = GraphFactory.open((String) configValue);
        } else if (configValue instanceof Map) {
            graph = GraphFactory.open((Map<String, Object>) configValue);
        } else {
            throw new IllegalArgumentException();
        }
        if (graph instanceof TinkerGraph) {
            final TinkerGraph tinkerGraph = (TinkerGraph) graph;
            tinkerGraph.createIndex(PROPERTY_USERNAME, Vertex.class);
            tinkerGraph.createIndex(PROPERTY_ATTRIBUTE_NAME, Vertex.class);
        }
        credentialStore = graph.traversal(ABACTraversalSource.class);
        logger.info("CredentialGraph initialized at {}", credentialStore);
    }

    @Override
    public AuthenticatedUser authenticate(final Map<String, String> credentials) throws AuthenticationException {
        final Vertex user;
        if (!credentials.containsKey(PROPERTY_USERNAME)) throw new IllegalArgumentException(String.format("Credentials must contain a %s", PROPERTY_USERNAME));
        if (!credentials.containsKey(PROPERTY_PASSWORD)) throw new IllegalArgumentException(String.format("Credentials must contain a %s", PROPERTY_PASSWORD));
        final String username = credentials.get(PROPERTY_USERNAME);
        final String password = credentials.get(PROPERTY_PASSWORD);
        final ABACTraversal<Vertex, Vertex> t = credentialStore.users(username);
        if (!t.hasNext()) throw new AuthenticationException("Username and/or password are incorrect");
        user = t.next();
        if (t.hasNext()) {
            logger.warn("There is more than one user with the username [{}] - usernames must be unique", username);
            throw new AuthenticationException("Username and/or password are incorrect");
        }
        final String hash = user.value(PROPERTY_PASSWORD);
        if (!BCrypt.checkpw(password, hash)) throw new AuthenticationException("Username and/or password are incorrect");
        List<String> attributes = credentialStore.attributes(username).values(PROPERTY_ATTRIBUTE_NAME).toList()
                .stream().map(String.class::cast).collect(Collectors.toList());
        return new ABACAuthenticatedUser(username, attributes);
    }
}

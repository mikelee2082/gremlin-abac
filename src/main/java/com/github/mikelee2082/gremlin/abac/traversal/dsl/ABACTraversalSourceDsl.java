package com.github.mikelee2082.gremlin.abac.traversal.dsl;

import org.apache.tinkerpop.gremlin.process.remote.RemoteConnection;
import org.apache.tinkerpop.gremlin.process.traversal.P;
import org.apache.tinkerpop.gremlin.process.traversal.TraversalStrategies;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Arrays;
import java.util.List;

import static com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalTokens.*;
import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.PROPERTY_USERNAME;
import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.VERTEX_LABEL_USER;

public class ABACTraversalSourceDsl extends GraphTraversalSource {
    public ABACTraversalSourceDsl(Graph graph, TraversalStrategies traversalStrategies) {
        super(graph, traversalStrategies);
    }

    public ABACTraversalSourceDsl(Graph graph) {
        super(graph);
    }

    public ABACTraversalSourceDsl(RemoteConnection connection) {
        super(connection);
    }

    public GraphTraversal<Vertex, Vertex> users() {
        return this.clone().V().hasLabel(VERTEX_LABEL_USER);
    }

    public GraphTraversal<Vertex, Vertex> users(final String username, final String... more) {
        if (more.length == 0) {
            return this.clone().V().has(VERTEX_LABEL_USER, PROPERTY_USERNAME, username);
        }
        final int lastIndex;
        final String[] usernames = Arrays.copyOf(more, (lastIndex = more.length) + 1);
        usernames[lastIndex] = username;
        return this.clone().V().has(VERTEX_LABEL_USER, PROPERTY_USERNAME, P.within(usernames));
    }

    public GraphTraversal<Vertex, Vertex> user(final String username, final String password) {
        return this.clone().V()
                .has(VERTEX_LABEL_USER, PROPERTY_USERNAME, username)
                .fold()
                .coalesce(__.unfold(),
                        __.addV(VERTEX_LABEL_USER)
                                .property(PROPERTY_USERNAME, username)
                                .property(PROPERTY_PASSWORD, BCrypt.hashpw(password, BCrypt.gensalt(ABACTraversal.BCRYPT_ROUNDS))));
    }

    public GraphTraversal<Vertex, Vertex> attribute(final String attributeName) {
        return this.clone().V().has(VERTEX_LABEL_ATTRIBUTE, PROPERTY_ATTRIBUTE_NAME, attributeName)
                .fold()
                .coalesce(__.unfold(),
                        __.addV(VERTEX_LABEL_ATTRIBUTE).property(PROPERTY_ATTRIBUTE_NAME, attributeName));
    }

    public GraphTraversal<Vertex, Vertex> authorize(final String username, final String attributeName, final String... more) {
        final String[] attributes = Arrays.copyOf(more, more.length + 1);
        attributes[more.length] = attributeName;
        return this.clone().V()
                .has(VERTEX_LABEL_USER, PROPERTY_USERNAME, username)
                .as(USER_STEP_LABEL)
                .V().has(VERTEX_LABEL_ATTRIBUTE, PROPERTY_ATTRIBUTE_NAME, P.within(attributes))
                .addE(ATTRIBUTE_EDGE_LABEL).from(USER_STEP_LABEL)
                .outV();

    }

    public GraphTraversal<Vertex, Vertex> attributes(final String username) {
        return this.users(username).out(ATTRIBUTE_EDGE_LABEL);
    }
}

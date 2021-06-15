package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.process.traversal.P;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.GremlinDsl;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Arrays;

import static com.github.mikelee2082.gremlin.abac.authz.ABACTraversalTokens.USER_STEP_LABEL;
import static org.apache.tinkerpop.gremlin.groovy.jsr223.dsl.credential.CredentialGraphTokens.*;

@GremlinDsl(traversalSource = "com.github.mikelee2082.gremlin.abac.authz.ABACTraversalSourceDsl")
public interface ABACTraversalDsl<S, E> extends GraphTraversal.Admin<S, E> {
    int BCRYPT_ROUNDS = 4;

    String VERTEX_LABEL_ATTRIBUTE = "attribute";
    String PROPERTY_ATTRIBUTE_NAME = "attributeName";
    String ATTRIBUTE_EDGE_LABEL = "hasAttribute";
    String ATTRIBUTE_STEP_LABEL = "attribute";

    /**
     * Finds all users
     */
    default GraphTraversal<S, Vertex> users() {
        return (ABACTraversal<S, Vertex>) hasLabel(VERTEX_LABEL_USER);
    }

    /**
     * Find specific users by username(s)
     */
    default GraphTraversal<S, Vertex> users(final String username, final String... more) {
        if (more.length == 0) {
            return (ABACTraversal<S, Vertex>) has(VERTEX_LABEL_USER, PROPERTY_USERNAME, username);
        }
        final int lastIndex;
        final String[] usernames = Arrays.copyOf(more, (lastIndex = more.length) + 1);
        usernames[lastIndex] = username;
        return (ABACTraversal<S, Vertex>) has(VERTEX_LABEL_USER, PROPERTY_USERNAME, P.within(usernames));
    }

    /**
     * Add a user with a password if a vertex with the same username does not exist
     */
    default GraphTraversal<S, Vertex> user(final String username, final String password) {
        return has(VERTEX_LABEL_USER, PROPERTY_USERNAME, username)
                .fold()
                .coalesce(__.unfold(),
                        __.addV(VERTEX_LABEL_USER).property(PROPERTY_USERNAME, username))
                .property(PROPERTY_PASSWORD, BCrypt.hashpw(password, BCrypt.gensalt(ABACTraversal.BCRYPT_ROUNDS)));
    }

    /**
     * Add a new attribute vertex if one with the same attribute name does not exist
     */
    /*
    default GraphTraversal<S, Vertex> attribute(final String attributeName) {
        return has(VERTEX_LABEL_ATTRIBUTE, PROPERTY_ATTRIBUTE_NAME, attributeName)
                .fold()
                .coalesce(__.unfold(),
                        __.addV(VERTEX_LABEL_ATTRIBUTE).property(PROPERTY_ATTRIBUTE_NAME, attributeName));
    }
    */
    /**
     * Create an edge between an attribute vertex and a user. It will create the attribute if it does not exist already
     */
    default GraphTraversal<S, Vertex> attribute(final String attributeName) {
        return hasLabel(VERTEX_LABEL_USER)
                .as(USER_STEP_LABEL)
                .V().has(VERTEX_LABEL_ATTRIBUTE, PROPERTY_ATTRIBUTE_NAME, attributeName)
                .addE(ATTRIBUTE_EDGE_LABEL).from(USER_STEP_LABEL)
                .outV();
    }

}

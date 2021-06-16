package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.driver.Tokens;
import org.apache.tinkerpop.gremlin.driver.message.RequestMessage;
import org.apache.tinkerpop.gremlin.jsr223.JavaTranslator;
import org.apache.tinkerpop.gremlin.process.traversal.Bytecode;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.authz.AuthorizationException;
import org.apache.tinkerpop.gremlin.server.authz.Authorizer;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalTokens.SECURITY_ATTRIBUTE_KEY_AND;
import static com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalTokens.SECURITY_ATTRIBUTE_KEY_OR;

import static org.junit.jupiter.api.Assertions.*;

class ABACAuthorizerTest {

    TinkerGraph graph;
    GraphTraversalSource g;

    @BeforeEach
    public void setup() {
        graph = TinkerGraph.open();
        g = graph.traversal();
    }

    @AfterEach
    public void teardown() {
        graph.close();
    }

    @Test
    public void shouldAddSubgraphStrategy() {
        final Bytecode bytecode = g.V().count().asAdmin().getBytecode();
        assertFalse(bytecode.toString().contains("SubgraphStrategy"));
        final Authorizer authorizer = new ABACAuthorizer();
        final List<String> userAttributes = List.of("ROLE1", "ROLE2", "ROLE3", "ROLE10");
        final AuthenticatedUser user = new ABACAuthenticatedUser("USER1", userAttributes);
        try {
            final Bytecode restrictedBytecode = authorizer.authorize(user, bytecode, Collections.emptyMap());
            assertTrue(restrictedBytecode.toString().contains("SubgraphStrategy"));
        } catch (AuthorizationException e) {
            fail(e);
        }
    }

    @Test
    public void shouldThrowExceptionIfBadUserImplementation() {
        final Bytecode bytecode = g.V().asAdmin().getBytecode();
        final Authorizer authorizer = new ABACAuthorizer();
        final AuthenticatedUser user = new AuthenticatedUser("USER1");
        assertThrows(AuthorizationException.class, () -> authorizer.authorize(user, bytecode, Collections.emptyMap()));
    }

    @Test
    public void shouldCorrectlyModifyBytecode() {
        final Vertex v1 = g.addV("DOG")
                .property("name", "Lassie")
                .property(SECURITY_ATTRIBUTE_KEY_AND, List.of("ROLE1", "ROLE3"))
                .property(SECURITY_ATTRIBUTE_KEY_OR, List.of("ROLE2", "ROLE5"))
                .next();
        final Vertex v2 = g.addV("DOG")
                .property("name", "Benji")
                .property(SECURITY_ATTRIBUTE_KEY_AND, List.of("ROLE4", "ROLE3"))
                .property(SECURITY_ATTRIBUTE_KEY_OR, List.of("ROLE2", "ROLE5"))
                .next();
        final List<String> userPrivileges = List.of("ROLE1", "ROLE2", "ROLE3");
        final AuthenticatedUser user = new ABACAuthenticatedUser("USER1", userPrivileges);
        final Bytecode bytecode = g.V().hasLabel("DOG").asAdmin().getBytecode();
        final Authorizer authorizer = new ABACAuthorizer();
        final JavaTranslator<GraphTraversalSource, GraphTraversal.Admin<?,?>> translator = JavaTranslator.of(g);
        try {
            final Bytecode restrictedBytecode = authorizer.authorize(user, bytecode, Collections.emptyMap());
            assertNotNull(restrictedBytecode);
            final GraphTraversal<?, ?> traversal = translator.translate(restrictedBytecode);
            final List<Vertex> vertices = traversal.toList().stream().map(Vertex.class::cast).collect(Collectors.toList());
            assertTrue(vertices.contains(v1));
            assertFalse(vertices.contains(v2));
        } catch (AuthorizationException e) {
            fail(e);
        }
    }

    @Test
    public void shouldThrowExceptionIfRequestMessageUsed() {
        final Authorizer authorizer = new ABACAuthorizer();
        final AuthenticatedUser user = new ABACAuthenticatedUser("USER1");
        final RequestMessage requestMessage = RequestMessage.build(Tokens.OPS_EVAL)
                .create();
        assertThrows(AuthorizationException.class, () -> authorizer.authorize(user, requestMessage));
    }
}
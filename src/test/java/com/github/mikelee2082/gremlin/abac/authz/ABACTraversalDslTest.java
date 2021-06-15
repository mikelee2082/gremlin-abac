package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import static com.github.mikelee2082.gremlin.abac.authz.ABACTraversalTokens.*;
import static org.junit.jupiter.api.Assertions.*;

public class ABACTraversalDslTest {

    @Test
    public void shouldCreateUser() {
        final Graph graph = TinkerGraph.open();
        final ABACTraversalSource g = graph.traversal(ABACTraversalSource.class);
        final Vertex v = g.user("user", "secret").next();
        assertEquals("user", v.value(PROPERTY_USERNAME));
        assertTrue(BCrypt.checkpw("secret", v.value(PROPERTY_PASSWORD)));
    }

    @Test
    public void shouldCreateAttribute() {
        final Graph graph = TinkerGraph.open();
        final ABACTraversalSource g = graph.traversal(ABACTraversalSource.class);
        final Vertex v = g.createAttribute("attribute").next();
        assertEquals("attribute", v.value(PROPERTY_ATTRIBUTE_NAME));
    }

    @Test
    public void shouldAddAttributeToUser() {
        final Graph graph = TinkerGraph.open();
        final ABACTraversalSource g = graph.traversal(ABACTraversalSource.class);
        final Vertex v1 = g.user("user", "secret").next();
        final Vertex v2 = g.attribute("user", "newAttribute").next();
        final long userCount = g.V().hasLabel(VERTEX_LABEL_USER).count().next();
        final long attributeCount = g.V().hasLabel(VERTEX_LABEL_ATTRIBUTE).count().next();
        final Edge e = g.V(v1).outE(ATTRIBUTE_EDGE_LABEL).next();
        assertEquals(v1, v2);
        assertEquals(1L, userCount);
        assertEquals(1L, attributeCount);
        assertNotNull(e);
    }

    @Test
    public void shouldAddAttributeToUserInMidTraversal() {
        final Graph graph = TinkerGraph.open();
        final ABACTraversalSource g = graph.traversal(ABACTraversalSource.class);
        final Vertex a1 = g.createAttribute("newAttribute").next();
        final Vertex v1 = g.user("thomas", "secret").next();
        g.users("thomas").attribute("newAttribute").iterate();
        assertEquals("thomas", v1.value(PROPERTY_USERNAME));
        final Vertex a2 = g.V(v1).out(ATTRIBUTE_EDGE_LABEL).next();
        assertEquals(a1, a2);
    }

}
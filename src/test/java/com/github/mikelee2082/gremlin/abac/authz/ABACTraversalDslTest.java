package com.github.mikelee2082.gremlin.abac.authz;

import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalSource;
import com.github.mikelee2082.gremlin.abac.traversal.dsl.__;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.structure.Edge;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import java.util.List;
import java.util.stream.Collectors;

import static com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalTokens.*;
import static org.junit.jupiter.api.Assertions.*;

public class ABACTraversalDslTest {

    private Graph graph;
    private ABACTraversalSource g;

    @BeforeEach
    public void setup() {
        graph = TinkerGraph.open();
        g = graph.traversal(ABACTraversalSource.class);
    }

    @AfterEach
    public void tearDown() {
        try {
            graph.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void shouldCreateUser() {
        final Vertex v = g.user("user", "secret").next();
        assertEquals("user", v.value(PROPERTY_USERNAME));
        assertTrue(BCrypt.checkpw("secret", v.value(PROPERTY_PASSWORD)));
    }

    @Test
    public void shouldCreateAttribute() {
        final Vertex v = g.attribute("attribute").next();
        assertEquals("attribute", v.value(PROPERTY_ATTRIBUTE_NAME));
    }

    @Test
    public void shouldAddAttributeToUserAtStart() {
        final Vertex v1 = g.user("user", "secret").next();
        final Vertex a1 = g.attribute("attribute1").next();
        final Vertex v2 = g.authorize("user", "attribute1").next();
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
        final Vertex a1 = g.attribute("newAttribute").next();
        final Vertex v1 = g.user("thomas", "secret").next();
        g.users("thomas").authorize("newAttribute").iterate();
        assertEquals("thomas", v1.value(PROPERTY_USERNAME));
        final Vertex a2 = g.V(v1).out(ATTRIBUTE_EDGE_LABEL).next();
        assertEquals(a1, a2);
    }

    @Test
    public void shouldRetrieveAllAttributesForUser() {
        final Vertex v1 = g.user("thomas", "secret").next();
        final List<String> attributeNames = List.of("ATTRIBUTE1", "ATTRIBUTE2", "ATTRIBUTE3");
        final List<Vertex> attributes = attributeNames
                .stream()
                .map(attributeName -> g.attribute(attributeName).next())
                .collect(Collectors.toList());
        final long attributeCount = g.V().hasLabel(VERTEX_LABEL_ATTRIBUTE).count().next();
        assertEquals(3L, attributeCount);
        g.authorize("thomas", "ATTRIBUTE1", "ATTRIBUTE2", "ATTRIBUTE3").iterate();
        final List<Object> authorizations = g.users("thomas").attributes().values(PROPERTY_ATTRIBUTE_NAME).toList();
        assertTrue(attributeNames.stream().allMatch(authorizations::contains));
    }

}
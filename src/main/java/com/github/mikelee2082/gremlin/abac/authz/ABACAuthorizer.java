package com.github.mikelee2082.gremlin.abac.authz;

import org.apache.tinkerpop.gremlin.driver.message.RequestMessage;
import org.apache.tinkerpop.gremlin.process.traversal.Bytecode;
import org.apache.tinkerpop.gremlin.process.traversal.P;
import org.apache.tinkerpop.gremlin.process.traversal.TraversalStrategy;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__;
import org.apache.tinkerpop.gremlin.process.traversal.strategy.decoration.SubgraphStrategy;
import org.apache.tinkerpop.gremlin.server.auth.AuthenticatedUser;
import org.apache.tinkerpop.gremlin.server.authz.AuthorizationException;
import org.apache.tinkerpop.gremlin.server.authz.Authorizer;

import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;

import static com.github.mikelee2082.gremlin.abac.authz.ABACTraversalTokens.SECURITY_ATTRIBUTE_KEY_AND;
import static com.github.mikelee2082.gremlin.abac.authz.ABACTraversalTokens.SECURITY_ATTRIBUTE_KEY_OR;

public class ABACAuthorizer implements Authorizer {

    @Override
    public void setup(Map<String, Object> config) {}

    @Override
    public Bytecode authorize(AuthenticatedUser user, Bytecode bytecode, Map<String, String> aliases) throws AuthorizationException {
        final ABACAuthenticatedUser abacUser;
        if (user instanceof ABACAuthenticatedUser) {
            abacUser = (ABACAuthenticatedUser) user;
        } else {
            throw new AuthorizationException("User should be instance of ABACAuthenticatedUser");
        }
        final List<String> securityAttributes = abacUser.getAttributes();
        final BiPredicate<List<String>, List<String>> andPredicate = (propertyList, userList) -> userList.containsAll(propertyList);
        final BiPredicate<List<String>, List<String>> orPredicate = (propertyList, userList) -> propertyList.stream().anyMatch(userList::contains);
        final Bytecode clone = bytecode.clone();
        final GraphTraversal filterTraversal = __.and(
            __.or(
                __.has(SECURITY_ATTRIBUTE_KEY_AND, P.test(andPredicate, securityAttributes)),
                __.hasNot(SECURITY_ATTRIBUTE_KEY_AND)),
            __.or(
                __.has(SECURITY_ATTRIBUTE_KEY_OR, P.test(orPredicate, securityAttributes)),
                __.hasNot(SECURITY_ATTRIBUTE_KEY_OR))
            );
        final TraversalStrategy<TraversalStrategy.DecorationStrategy> strategy = SubgraphStrategy.build()
                .vertices(filterTraversal)
                .edges(filterTraversal)
                .vertexProperties(filterTraversal)
                .create();
        clone.addSource("withStrategies", strategy);
        return clone;
    }

    @Override
    public void authorize(AuthenticatedUser user, RequestMessage msg) throws AuthorizationException {
        throw new AuthorizationException("This Authorizer only handles bytecode-based requests.");
    }
}

package com.github.mikelee2082.gremlin.abac.console;

import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversal;
import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalDsl;
import com.github.mikelee2082.gremlin.abac.traversal.dsl.ABACTraversalSource;
import org.apache.tinkerpop.gremlin.jsr223.*;

public class ABACCredentialPlugin extends AbstractGremlinPlugin {

    private static final String NAME = "mikelee2082.abac.credentials";
    private static final ImportCustomizer imports = DefaultImportCustomizer.build()
            .addClassImports(
                    ABACTraversalSource.class,
                    ABACTraversal.class,
                    ABACTraversalDsl.class
            ).create();
    private static final ABACCredentialPlugin instance = new ABACCredentialPlugin();

    public ABACCredentialPlugin() {
        super(NAME, imports);
    }

    @Override
    public String getName() {
        return NAME;
    }

    public static ABACCredentialPlugin instance() {
        return instance;
    }
}

package com.github.mikelee2082.gremlin.abac.authz;

public final class ABACTraversalTokens {

    public static final String VERTEX_LABEL_USER = "user";
    public static final String PROPERTY_USERNAME = "username";
    public static final String PROPERTY_PASSWORD = "password";
    public static final String VERTEX_LABEL_ATTRIBUTE = "attribute";
    public static final String PROPERTY_ATTRIBUTE_NAME = "attributeName";
    public static final String ATTRIBUTE_EDGE_LABEL = "hasAttribute";
    public static final String ATTRIBUTE_STEP_LABEL = "attribute";
    public static final String USER_STEP_LABEL = "user";

    public static final String SECURITY_ATTRIBUTE_KEY_AND = "andSecurityAttributes";
    public static final String SECURITY_ATTRIBUTE_KEY_OR = "orSecurityAttributes";
}

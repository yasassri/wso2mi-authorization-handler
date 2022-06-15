package com.ycr.auth.handlers;

public class AuthConstants {

    //Response Status Codes
    public static final int SC_UNAUTHORIZED = 401;
    public static final int SC_FORBIDDEN = 403;

    //Response Header Strings
    public static final String HTTP_STATUS_CODE = "HTTP_SC";
    public static final String RESPONSE = "RESPONSE";
    public static final String TRUE = "true";
    public static final String NO_ENTITY_BODY = "NO_ENTITY_BODY";
    public static final String WWW_AUTHENTICATE = "WWW_Authenticate";
    public static final String WWW_AUTH_METHOD = "Basic realm=\"WSO2 EI\"";
}

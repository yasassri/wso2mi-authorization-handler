package com.ycr.auth.handlers;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.wso2.micro.integrator.security.MicroIntegratorSecurityUtils;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import org.wso2.micro.integrator.security.user.api.UserStoreManager;

import java.util.Map;

public class AuthorizationHandler implements Handler {

    private static final Log log = LogFactory.getLog(AuthorizationHandler.class);
    private static final String AUTH_FAILED_MESSAGE = "Authentication failed.";

    private String[] allowedRoles;
    private boolean doAuthorize;

    @Override
    public boolean handleRequest(MessageContext messageContext) {

        org.apache.axis2.context.MessageContext axis2MessageContext
                = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            if (headersMap.get(HTTPConstants.HEADER_AUTHORIZATION) == null) {
                log.error(AUTH_FAILED_MESSAGE + HTTPConstants.HEADER_AUTHORIZATION + " header does not exist.");
                headersMap.clear();
                axis2MessageContext.setProperty(AuthConstants.HTTP_STATUS_CODE, AuthConstants.SC_UNAUTHORIZED);
                headersMap.put(AuthConstants.WWW_AUTHENTICATE, AuthConstants.WWW_AUTH_METHOD);
                axis2MessageContext.setProperty(AuthConstants.NO_ENTITY_BODY, true);
                messageContext.setProperty(AuthConstants.RESPONSE, AuthConstants.TRUE);
                messageContext.setTo(null);
                Axis2Sender.sendBack(messageContext);
                return false;
            } else {
                String authHeader = (String) headersMap.get(HTTPConstants.HEADER_AUTHORIZATION);
                String credentials = authHeader.substring(6).trim();
                String decodedCredentials = new String(new Base64().decode(credentials.getBytes()));

                if (decodedCredentials.contains(":")) {
                    String username = decodedCredentials.split(":")[0];
                    String password = decodedCredentials.split(":")[1];
                    if (username.length() != 0 && password.length() != 0) {
                        if (authenticateUser(username, password)) {
                            // Only authorize if authorization is enabled
                            if (doAuthorize) {
                                if (authorizeUser(username, password)){
                                    return true;
                                } else {
                                    log.error("Authorization failed for the user : " + username);
                                    headersMap.clear();
                                    axis2MessageContext.setProperty(AuthConstants.HTTP_STATUS_CODE, AuthConstants.SC_FORBIDDEN);
                                    axis2MessageContext.setProperty(AuthConstants.NO_ENTITY_BODY, true);
                                    messageContext.setProperty(AuthConstants.RESPONSE, AuthConstants.TRUE);
                                    messageContext.setTo(null);
                                    Axis2Sender.sendBack(messageContext);
                                    return false;
                                }
                            }
                            return true;
                        } else {
                            log.error(AUTH_FAILED_MESSAGE + " Authentication failed for the user : " + username);
                            headersMap.clear();
                            axis2MessageContext.setProperty(AuthConstants.HTTP_STATUS_CODE, AuthConstants.SC_UNAUTHORIZED);
                            axis2MessageContext.setProperty(AuthConstants.NO_ENTITY_BODY, true);
                            messageContext.setProperty(AuthConstants.RESPONSE, AuthConstants.TRUE);
                            messageContext.setTo(null);
                            Axis2Sender.sendBack(messageContext);
                            return false;
                        }
                    }
                }
                log.error(AUTH_FAILED_MESSAGE + " Username or password provided not in the correct format.");
                headersMap.clear();
                axis2MessageContext.setProperty(AuthConstants.HTTP_STATUS_CODE, AuthConstants.SC_UNAUTHORIZED);
                axis2MessageContext.setProperty(AuthConstants.NO_ENTITY_BODY, true);
                messageContext.setProperty(AuthConstants.RESPONSE, AuthConstants.TRUE);
                messageContext.setTo(null);
                Axis2Sender.sendBack(messageContext);
                return false;
            }
        }
        log.error(AUTH_FAILED_MESSAGE + " Could not authenticate due to missing headers in request.");
        return false;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return false;
    }

    @Override
    public void addProperty(String s, Object o) {
    }

    @Override
    public Map getProperties() {
        return null;
    }

    /**
     * This method authenticates credentials
     *
     * @param credentials credentials The Basic Auth credentials of the request
     * @return true if the credentials are authenticated successfully
     */
    private boolean authenticateUser(String userName, String password) {
        UserStoreManager userStoreManager;
        try {
            userStoreManager = MicroIntegratorSecurityUtils.getUserStoreManager();
        } catch (UserStoreException e) {
            log.error("Error occurred while retrieving User Store Manager", e);
            return false;
        }
        try {
            return userStoreManager.authenticate(userName, password);
        } catch (UserStoreException e) {
            log.error("Error in authenticating user", e);
            return false;
        }
    }

    /**
     * This method Authorizes the user
     *
     * @param userName username of the user
     * @param password password of the user
     * @return true if the authorization is successful
     */
    private boolean authorizeUser(String userName, String password) {
        try {
            UserStoreManager userStoreManager = MicroIntegratorSecurityUtils.getUserStoreManager();
            String[] userAssignedRoles = userStoreManager.getRoleListOfUser(userName);
            for (String role : userAssignedRoles) {
                for (String allowedRole : allowedRoles) {
                    if (role.equals(allowedRole)) {
                        return true;
                    }
                }
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while retrieving Roles or User Store Manager", e);
        }
        return false;
    }

    public void setRoles(String roles) {
        allowedRoles = roles.split(",");
    }

    public void setAuthorize(String authorize) {
        doAuthorize = Boolean.parseBoolean(authorize);
    }
}

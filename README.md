# wso2mi-authorization-handler

This WSO2 synapse handler allows to do authentication and role based authorization

**How to use**

1. First build this project or download the released Jar from https://github.com/yasassri/wso2mi-authorization-handler/releases/tag/v1.0.0 and copy the wso2-authorization-handler-1.0.jar to <MI_HOME>/lib directory.
2. Then in the API definition you can add the handler as shown below.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<api xmlns="http://ws.apache.org/ns/synapse" name="test2" context="/test2" binds-to="default">
   <resource methods="POST" binds-to="default">
      <inSequence>
         <payloadFactory media-type="xml">
            <format>
               <soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope"
                                 xmlns:ns="http://www.viewstar.com/webservices/2002/11">
                  <soapenv:Header/>
                  <soapenv:Body>
                     <ns:placeOrder>
                        <ns:order>
                           <ns:symbol>$1</ns:symbol>
                        </ns:order>
                     </ns:placeOrder>
                  </soapenv:Body>
               </soapenv:Envelope>
            </format>
            <args>
               <arg evaluator="json" expression="$.code"/>
            </args>
         </payloadFactory>
         <respond/>
      </inSequence>
      <outSequence/>
      <faultSequence/>
   </resource>
   <handlers>
    <handler class="com.ycr.auth.handlers.AuthorizationHandler">
      <property name="roles" value="admin,test" />
      <property name="authorize" value="true" />
    </handler>
</handlers>
</api>
```
3. Then Add a user credentials as a Basic Auth header and send a request. Refer following. (Make sure user:password is base64 encoded)

`curl -vk -X POST http://localhost:8290/test2 -H "Authorization: Basic YWRtaW46YWRtaW4="`

Note: If the Authentication fails you will get a HTTP 401 or if the Authorization fails you will receive a HTTP 403.

**Handler params.**

```xml
<handler class="com.ycr.auth.handlers.AuthorizationHandler">
      <property name="roles" value="admin,test" />
      <property name="authorize" value="true" />
</handler>
```

- **roles**: The user can define list of allowed roles for the API.
- **authorize**: If Aauthorization(Role validation) is not required this can be set to false. If set to false only authentication will take place. Authorization stage will be skipped. 

Note: Inorder to do role management you need to plugin a LDAP or a JDBC userstore to MI.

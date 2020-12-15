# Use case
## Example
- Three IdPs exits
  - RP1-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/rp1-idp)
    - this IdP is authenticate the user (alice), and issues the assertion to RP1
      - RP1 identifies the user using this assertion
  - CAP1-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/cap1-idp)
    - this IdP is authenticate the user (alice), and issues the assertion to CAP1
    - CAP1 identifies the user using thie assertion
  - Context-Share-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share)
    - this IdP is authenticate the user (alice), and issues the assertion to CAP1 and RP1
      - RP1 and CAP1 identifies whose contexts when sharing contexts
      - also this IdP is UMA Authorization Server
        - authenticate the requesting party (rp1), and issues the assertion to RP1
- CAP1 handles two kind of contexts
  - context identifier `ctx-1`, scope `scope1` and `scope2`
  - context identifier `ctx-2`, scope `scope111` and `scope2`
- CAP1 deploys its agent to user's device
  - the agent collect user's context, and notify to CAP when updated
- User want to access to RP1
- For access control, RP1 makes authorization decisions using two kind of contexts from CAP1


## Scenario
1. User tries to access to RP1
2. User set the following policy in UMA authorization server (Context-Share-IdP)
   - approve that CAP1 provide contexts for RP1
3. RP1 receives contexts from CAP1 under user control
4. CAP transmits updated context to RP1 when nortified by CAP agent deploying at User device
5. RP1 shares updated contexts via CAP1, then makes re-authorization decision using the contexts

## Step-by-Step Description
### 0. User Registers contexts managed by CAP1 with UMA Authorization Server
In order to control sharing contexts managed by CAP1, User uses UMA Authorization Service of Context-Share-IdP
Because this authorization service compliant [Federated Authorization for User Managed Access(UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html), User can register User's contexts managed by CAP1 as UMA protected resources.

Prior to registration, User access to CAP1 (http://cap1.ztf-proto.k3.ipv6.mobi/).
Altough User never access to CAP1, CAP1 redirects to CAP1-IdP for authentication.


![Login Page at CAP1-IdP](assets/cap1_initial_access.png)
User inputs the credential (name: `alice-cap1`, pass: `alice`).
the IdP authenticates User and redirect back to CAP1 following OpenID Connect Flow, and CAP1 identifies User.

![Welcome page at CAP1](assets/cap1_login.png)
When login succeeded, you can confirm that CAP1 get the identity about User.
Next, User clicks the registration link so that User can register User's contexts with UMA authorization server (Context-Share-IdP).

![Login Page at Context-Share-IdP](assets/cap1_context_reg.png)
Because User never provides the Identity within Context-Share-Idp with CAP1, CAP1 does not know User's Identity within Context-Share-IdP.
CAP1 redirect User to the IdP to identify User within the IdP domain.

User inputs the credential (name: `alice-share`, pass: `alice`), and the IdP authenticates User.

![CAP1 コンテキスト登録画面](assets/cap1-context-no-reg.png)
When login succeeded, CAP1 can register User's contexts behalf on User.
When User tap 「保護する (meaning "Do Protection")」Button, CAP1 registers User's contexts with the identity to [UMA Protection API Resource Registration Endpoint](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#resource-registration-endpoint) in Context-Share-IdP. 

To register the context of this identifier `ctx-1` behalf on User (alice), CAP1 sends the following HTTP Request to UMA authorization server.
Authorizatoin Header of this HTTP Request has UMA Protection API Token (PAT).
Using this PAT, the authorization server understands who want to register (in this case, CAP1).

Note: `owner` and `ownerManagedAccess` of the Request body is specific to KeyCloak, which spscify the owner of this resource.

```http
POST /auth/realms/context-share/authz/protection/resource_set HTTP/1.1
HOST: idp.ztf-proto.k3.ipv6.mobi
Content-Type: application/json
Authorization: Bearer eyHjXXXXXXX
{
  "name": "sub:alice-share:ctx:ctx-1",
  "scopes": ["scope1", "scope2"],
  "owner": "26ba8184-895f-420d-8591-611784805fe3",
  "onwerManagedAccess": true
}
```

You can confrim the information about registered contexts at CAP1.
![Confirm the registered context to UMA Authorization Server at CAP1](assets/cap-context-1-registered.png)
ID is assigned by UMA Authorization server, and CAP1 can manage registered context at the Server using this ID.

Also, you can confirm the information about registered contexts at the Server.
![Confirm the registered context at UMA Authorization Server (Context-Share-IdP)](assets/idp-context-resource.png)
you can confirm that the owner of this context is User alice (name: `alice-share`).

At this point, User registers contexts managed by CAP1 to UMA Authorization Server (Context-Share-IdP).


# 1. User access to RP1
User tries to access to RP1(http://rp1.ztf-proto.k3.ipv6.mobi/).
Althogh RP1 wants to make authorization decision, RP1 cannot understand who access.
RP1 redirects User to RP1-IdP for authentication.

![Login Page at RP1-IdP](assets/rp1-initial_login.png)
User inputs the credential (user: `alice-rp1`, pass: `alice`), and the IdP authenticates User.
The IdP redirects back to RP1, and RP1 gets the User's identity.

Now RP1 understand who access what resources, but RP1 does not make authorization decisions in order not to know User's contexts.
Because RP1 need contexts collected and managed by CAP1 for authorization, RP1 tries to get contexts from CAP1 by registering User with CAP1.

RP1 redirects User to Context-Share-IdP for getting User's identity for the registration.

![Login Page at Context-Share-IdP](assets/rp1-context-share-login.png)
User inputs the credential (user: `alice-share`, pass: `alice`), and the IdP authenticates User.

RP1 requests contexts to CAP1 with the User's identity.
this step follows Adding Subject of Continuous Access Evaluation Protocol (CAEP).

RP1 access as CAEP receiver to  [SET Event Stream Management API](https://tools.ietf.org/html/draft-scurtescu-secevent-simple-control-plane-00) of CAP.

RP1 configures RP1's Stream Settings to CAP Stream Management API.
Then, RP1 tries to add User to this strem (if adding succeeded, RP1 can receive contexts about User).



RP1 sends the following HTTP Request to CAP1 for adding User to the Event Stream.
```http
POST /set/subject:add HTTP/1.1
HOST: cap1.ztf-proto.k3.ipv6.mobi
Content-Type: application/json

{
  "subject": {
    "subject_type": "spag",
    "spag_id": "26ba8184-895f-420d-8591-611784805fe3"
  },
  "events_scopes_requested": {
    "ctx-1": ["scope1", "scope2"],
    "ctx-2": ["scope111", "scope2"]
  }
}
```
the HTTP Request does not have Authorization Header.
This means that RP1 is not authorized for accessing contexts by UMA Authorization Server.

Then, CAP1 starts [UMA Grant Flow](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html).

Prior to starting the Grant Flow, CAP1 gets a UMA Permission Ticket from UMA Authorization Server.
Because CAP1 can determine what contexts and its scopes RP1 want, CAP1 can understand what permissions RP1 needs.

CAP1 sends the following HTTP Request to UMA Authoriaztion Server (Context-Share-IdP)
```http
POST /auth/realms/context-share/authz/protection/permission HTTP/1.1
Host: idp.ztf-proto.k3.ipv6.mobi
Content-Type: application/json
Authorization: Bearer eyHjXXXXXXX

{  
   "resource_id":"abb30ff1-ee23-4b8f-acb2-04b0b5f3989b",
   "resource_scopes":["scope1", "scope2"]
}
```

Then, the authorization server issues the Permission Ticket.
CAP1 responds to RP1 with the Permission Ticket and the Issuer.
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: UMA realm="cap1.ztf-proto.k3.ipv6.mobi",
  as_uri="http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share",
  ticket="eyJhYYYYYYYYYYYYYYYYYYY"
```


RP1 can understand why RP1 fail to add User From HTTP Status Code.
RP1 tries to be granted authorization.

RP1 sends the following HTTP Request to UMA Authorization Server.
The Authorization Header of this Request is set UMA Clinet Credential as the same when requesting token in OAuth2.0 Client Credential Grant Flow.
The `grant_type` parameter is set `urn:ietf:params:oauth:grant-type:uma-ticket`, which represents that this grant request is UMA Grant Authorization.
The `ticket` parameter is set the Permission Ticket.
The `claim_token` parameter is set OpenID Connect IDToken of the requesting party (user: `rp1`) issued by Context-Share-IdP.
```http
POST /auth/realms/context-share/protocol/openid-connect/token HTTP/1.1
Host: idp.ztf-proto.k3.ipv6.mobi
Authorization: Basic cnAxOnJwMV9zZWNyZXRfZm9yX2NvbnRleHRfc2hhcmVfaWRw
grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
&ticket=eyJhYYYYYYYYYYYYYYYYYYY
&claim_token=eyJZZZZZZZZZZZZZZZZZZZZZ
&claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken
```

The Authorization Server tries to make an authorization decision whether the server issues an UMA Requesting Party Token.
However, the server fail to make decisions because User never set the policy about RP1.

Then the server responds an error to RP1.
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{  
   "error": "access_denied",
   "error_description":"request_submitted",
}
```

RP1 notifies that User does not set the policy about RP1.
![Notification of User](assets/rp1_ctx_req_submitted.png)

# 2. User set the policy about RP1 in the Authorization Server
User uses Keycloak's built-in policy settings.
Keycloak allows User to choose whether to approve or deny the Requesting Party's request for each resource.
In addition, when approving, it is possible to limit the scope of the request to be approved.

![Policy Setting](assets/idp_policy_set.png)

User approves:
  - RP1 understands the context of identifier `ctx-1` only scoped `sope1`
  - RP1 understands the context of identifier `ctx-2`


# 3. RP1 receives User's contexts from CAP1
User re-access to RP1.
RP1 sends the provious HTTP Request again to the Authorization server for RPT.

At this point, User already have set the policy.
The Authorization server can make an authorization decision and issues the RPT.



RP1 send the following HTTP Request to CAP1 with granted RPT.
```http
POST /set/subject:add HTTP/1.1
HOST: cap1.ztf-proto.k3.ipv6.mobi
Content-Type: application/json
Authorization: Bearer eyJhVVVVVVVVVVVVVVVVVVV

{
  "subject": {
    "subject_type": "spag",
    "spag_id": "26ba8184-895f-420d-8591-611784805fe3"
  },
  "events_scopes_requested": {
    "ctx-1": ["scope1", "scope2"],
    "ctx-2": ["scope111", "scope2"]
  }
}
```

CAP1 verifies the RPT and validates the request for adding User.
In this case, the RPT restricts `ctx-1` to only `sope1`.
CAP1 registers User to RP1's Event Stream restriced with only `sope1`.

CAP1 transmits the following [SET](https://tools.ietf.org/html/rfc8417) to RP1 for sharing contexts about User.
```HTTP
POST /auth/pip/ctx/0/recv HTTP/1.1
HOST: rp1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoic2NvcGUxOnZhbHVlIn19fX0.
SiGV0pK3rF3CAUrGABqvyHrP-zYE9zOrBNQdMBW9TPw
```
Decoding the jwt payload, following:
```json
{
  "aud": ["http://rp1.ztf-proto.k3.ipv6.mobi"],
  "iat": 1606330790,
  "iss": "http://cap1.ztf-proto.k3.ipv6.mobi",
  "jti": "metyakutya-random",
  "events": {
    "ctx-1": {
      "subject": {
        "subject_type": "spag",
        "spag_id": "26ba8184-895f-420d-8591-611784805fe3"
      },
      "property": {
        "scope1": "scope1:value"
      }
    }
  }
}
```
Note: As User Control, CAP1 only transmits `ctx-1` with `scope1`.


Finally, RP1 makes an authorization decisin based on received contexts about User.

RP1 log is following:
```
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): scope1:value
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value
```

# 4. The CAP1 agent notifies updated contexts of CAP1 
In this prototype, the CAP agent is simple.

the agent can send the following request to CAP1.
```HTTP
POST /ctx/recv HTTP/1.1
HOST: cap1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiY2FwMSJdLCJpc3MiOiJjYXAxLWFnZW50IiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEiLCJzY29wZTIiOiJuZXd3d3d3d3d3d3ctdmFsdWVlZWVlISEhISJ9fX19.
XWS3y5QvX1CTYuc5CWvgwOvIOtgOJSIqSadzdXayYmQ
```
Decoding the jwt payload, following:
```json
{
  "aud": ["cap1"],
  "iss": "cap1-agent",
  "events": {
    "ctx-1": {
      "subject": {
        "subject_type": "spag",
        "spag_id": "26ba8184-895f-420d-8591-611784805fe3"
      },
      "property": {
        "scope1": "new-value!!!!!",
        "scope2": "newwwwwwwwww-valueeeee!!!!"
      }
    }
  }
}
```

the agent notifies that the value of `ctx-1` is updated.

When receiving the updated context, CAP1 updates managed contexts about User.

# 5. RP1 shares the updated contexts via CAP1
When the context updated, CAP1 transmits the updated context to RP who need to know the change.

CAP1 sends the following request to RP1 because RP1 is permitted accessing the context (`ctx-1`) by User.
```http
POST /auth/pip/ctx/0/recv HTTP/1.1
HOST: rp1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMTAzMiwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEifX19fQ.
sVL7FkA3eLgxQ7yUvvmuk3P2TiD1UfR_congU2RXiRE
```
Decoding the jwt payload, following:
```json
{
  "aud": ["http://rp1.ztf-proto.k3.ipv6.mobi"],
  "iat": 1606331032,
  "iss": "http://cap1.ztf-proto.k3.ipv6.mobi",
  "jti": "metyakutya-random",
  "events": {
    "ctx-1": {
      "subject": {
        "subject_type": "spag",
        "spag_id": "26ba8184-895f-420d-8591-611784805fe3"
      },
      "property": {
        "scope1": "new-value!!!!!"
      }
    }
  }
}
```
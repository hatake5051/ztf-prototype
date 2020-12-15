# ZTF-Protptype
Prototype for my study

## Description of the use case
https://github.com/hatake5051/ztf-prototype/blob/percom/example/usecase.md

## How To Run
This example assumes followings
- running on a single physical host.
  - the host is assinged `ztf-proto.k3.ipv6.mobi` 
- DNS Record `*.ztf-proto.k3.ipv6.mobi. IN  CNAME ztf-proto.k3.ipv6.mobi.`
- deploy by using docker

create docker network.
```bash
$ docker network create reverse-proxy-net
```

In order to deploy vertial hosts(for RP, IdP and CAP) on the single physical host, we prepare a rever-proxy.
we use https://github.com/nginx-proxy/nginx-proxy as a reverse-proxy.

build reverse-proxy by using docker-compose.
```bash
$ pwd
/ztf-prototype/example/rever-proxy
$ docker-compose up
```

### building IdP
We use Keycloak(https://www.keycloak.org/) to build an IdP.

build the IdP by using docker-compose.
```bash
$ pwd
/ztf-prototype/example/idp 
$ docker-compose up
```

we can access to IdP at idp.ztf-proto.k3.ipv6.mobi.

initial configuration about the IdP.
- make three realms (in Keycloak, identity management is divided into each realm)
  - for login to RP
  - for login to CAP
  - for sharing context between RP and CAP

#### IdP configuration for login to RP
1. make `rp1-idp` realm
2. create new client
   - client ID is `rp1`
   - confidential client
     - redirect url is `http://rp1.ztf-proto.k3.ipv6.mobi/auth/pip/sub/0/callback`
3. set auto-generated client secret `pip.sub.rp_config.client_secret` at `ztf-prototype/actors/rp/cmd/conf.json`
4. create a test user
  - name: `alice-rp1`
  - password: `alice`

#### IdP configuration for login to CAP
1. make `cap1-idp` realm
2. create new client
   - client ID is `cap1`
   - confidential client
     - redirect url is `http://cap1.ztf-proto.k3.ipv6.mobi/oidc/callback`
3. set auto-generated client secret `cap.openid.rp_secret` at `ztf-prototype/actors/cap/cmd/conf.json`
4. create a test user
  - name: `alice-cap1`
  - password: `alice`

#### IdP configuration for context sharing between RP and CAP
1. make `context-share` realm
  - configure User-Managed Access `ON` at General Tab in Realm Settings
    - because of using this realm as UMA authorization server
2. create new clients
  - client ID is `rp1`
    - configure service account enabled `ON`
      - because this client request UMA Requesting Party Token to the token endpoint following Client Credential Grant Flow
    - redirect url is `http://rp1.ztf-proto.k3.ipv6.mobi/auth/pip/ctx/0/callback`
    - set auto-generated client secret at ztf-prototype/actors/rp/cmd/conf.json
      - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".authN.rp_config.client-secret`
      - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".recv.oauth2.client-secret`
      - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".recv.uma.client_credential.secret`
  - client ID is `cap1`
    - configure authorization enabled `ON`
      - because this client serves as UMA resource server
    - configure service account enabled `ON`
      - because this client request UMA Protection API Token to the token endpoint following Cilent Credential Grant Flow
    - redirect url is `http://cap1.ztf-proto.k3.ipv6.mobi/uma/oidc/callback`
    - set auto-generated client secret at ztf-prototype/actors/cap/cmd/conf.json
      - `uma.client_secret`
      - `caep.openid.rp_secret`
    - delete Default Resource at the Resource Tag on the Authorization Setting Tag
3. create a user
  - UMA requesting party
    - Because in Keycloak, UMA Grant Flow requires requesting party information to determinie an authorization decision
    - name: `rp1`
    - password: `rp1`
  - test user
    - name: `alice-share`
    - password: `alice`

### build CAP and RP
```bash
$ pwd
/ztf-prototype/example/cap
$ docker-compose up
```

```bash
$ pwd
/ztf-prototype/example/rp
$ docker-compose up
```

fin.
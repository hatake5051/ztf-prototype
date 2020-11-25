# プロトタイプのユースケース
今回は、次のようなユースケースを想定し、コンテキストの共有がユーザの制御下にあることを確認した。

## 前提
- IdP は３つ存在する
  - RP1-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/rp1-idp)
    - ユーザが RP1 へアクセスする際に、 RP1 がユーザ認証情報を取得するために使う
  - CAP1-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/cap1-idp)
    - ユーザが CAP1 へアクセスする際に、 CAP1 がユーザ認証情報を取得するために使う
  - Context-Share-IdP(http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share)
    - RP1 と CAP1 がコンテキスト共有を行う際に、ユーザ認証情報を取得するために使う
    - このIdP は UMA 認可サーバを兼ねる
- CAP1 は二つのコンテキストを扱う
  - コンテキスト識別子`ctx-1`:  
    - これには `scope1, scope2` という２つのスコープが用意されている
  - コンテキスト識別子`ctx-2`:  
    - これには `scope111, scope2` という２つのスコープが用意されている
- CAP1 はエージェントをユーザのデバイスに配備している
  - エージェントはユーザのコンテキスト情報を取得し、更新があればそれを CAP1 へ送信する
- ユーザは RP1 へアクセスする
- RP1 はアクセス制御を行うために、 CAP1 が提供する2つのコンテキストを使う

## シナリオ
1. ユーザは RP1 にアクセスする
1. ユーザは Context-Share-IdP にあるUMA認可サーバに「CAP から RP1 へのコンテキスト提供を承認する」ポリシーを設定する
1. RP1 はユーザ制御下でコンテキストの提供を CAP から受ける
1. CAP のエージェントはコンテキストの更新を検知し、それを CAP へ伝える
1. RP1はCAPを介して更新されたコンテキストを共有する

## 実際の動作
### 0. ユーザは CAP1 にあるコンテキストを UMA 認可サーバに登録する
ユーザは CAP1 にあるコンテキストの共有を制御するために Context-Share-IdP の UMA 認可サービスを使う。
この認可サービスは [Federated Authorization for User Managed Access(UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html) に対応しているため、 CAP1 にあるユーザのコンテキストを UMA リソースとして登録することができる。

登録するために、まずユーザは CAP1(http://cap1.ztf-proto.k3.ipv6.mobi/) へアクセスする。
しかし、ユーザはまだ CAP1 に対して認証情報を提供していないため、 CAP1 はユーザを CAP1-IdP へリダイレクトする。

![CAP1-IdP のログイン画面](assets/cap1_initial_access.png)
クレデンシャル(`alice-cap1:alice`)を入力し、認証を成功させる。
すると、OpenID Connect のフローに従って CAP1 はユーザの認証情報を取得できる。

![CAP1 の Welcome page](assets/cap1_login.png)
ログインに成功すると、認証情報を取得していること(名前が `alice-cap1` であること)、またコンテキストを管理するためのリンクが確認できる。
今回は、コンテキストを UMA リソースとして UMA 認可サーバに管理してもらうため、その登録を行う。リンクをクリックする。

![Context-Share-IdP のログイン画面](assets/cap1_context_reg.png)
リンクをクリックすると、 Context-Share-IdP の認証画面へリダイレクトされる。
これは、 UMA 認可サーバにリソースを登録する際、 Context-Share-IdP の identity を使って登録を行うためである。
クレデンシャル(`alice-share:alice`)を入力し、認証を成功させる。

![CAP1 コンテキスト登録画面](assets/cap1-context-no-reg.png)
ログインに成功すると、認証情報を取得していること(名前が `alice-share` であること)、またコンテキストを管理するためのリンクが確認できる。
まだ、このユーザはコンテキストを認可サーバにリソースとして登録していないため、その登録を行う。
登録は UMA Protection API の [Resource Registration Endpoint](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#resource-registration-endpoint) を使って行う。

例えば、コンテキスト識別子 ctx-1 のコンテキストを登録する際は次のようなHTTP Request をUMA認可サーバへ送信する。
Authorization ヘッダーには PAT トークンを添付して送信する。これトークンによって認可サーバはリソースサーバの情報を取得できる。
また、Request Body にある `owner` と `ownerManagedAccess` は Keycloak 特有のもので、このリソースの所有者を指定できる。
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
また、 登録したコンテキストの情報は次のように確認できる。
![CAP1 で認可サーバに登録したコンテキストを確認する](assets/cap-context-1-registered.png)
ID は認可サーバが割り振る値で、今後はこのIDを使ってリソースを管理する。

さらに、登録したコンテキストを認可サーバでも確認すると次。
![Context-Share-IdP で CAP1 が登録したコンテキストを確認する](assets/idp-context-resource.png)
確かにこのコンテキストの所有者が `alice-share` であることが確認できる。

以上で、 CAP1 のコンテキスト情報を Context-Share-IdP の認可サーバに登録することができた。

# 1. ユーザは RP1 にアクセスする
ユーザは RP1(http://rp1.ztf-proto.k3.ipv6.mobi/) へアクセスする。
しかし、ユーザはまだ RP1 に対して認証情報を提供していないため、 RP1 はユーザを RP1-IdP へリダイレクトする。

![RP1-IdP のログイン画面](assets/rp1-initial_login.png)
クレデンシャル(`alice-rp1:alice`)を入力し、認証を成功させる。

認証に成功すると、 RP1 のアクセス制御部は identity を取得できる。
identity を取得すると、 RP1 のアクセス制御部は次にアクセス可否の判断に必要なコンテキスト情報を CAP1 から取得しようと試みる。
CAP1 からコンテキスト情報を取得するためには、 RP1 は Context-Share-IdP が発行するユーザの認証情報を必要とする。
そのため、ユーザはリダイレクトされる。

![Context-Share-IdP のログイン画面](assets/rp1-context-share-login.png)
クレデンシャル(`alice-share:alice`)を入力し、認証を成功させる。

RP1 は CAP1 とコンテキストを共有するために必要なユーザ識別子を取得できたため、コンテキストを要求する。
コンテキストの要求は Continuous Access Evaluation Protocol を用いる。
RP1 は CAEP の Receiver として CAP の [SET Event Stream Management API](https://tools.ietf.org/html/draft-scurtescu-secevent-simple-control-plane-00) にアクセスする。
必要な Stream 設定情報を更新し終わると、このユーザの登録を試みる。登録によって RP1 は CAP1 からコンテキストの提供を受けることができる。

ユーザの登録要求は次のHTTP要求で行われる。
しかし、この要求には Authorization ヘッダーがついていない。
つまり、まだ RP1 はこのコンテキストへのアクセス要求に関する許可を得ていないことになる。
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

従って、 CAP1 は UMA Grant フローを開始する。
開始するにあたって、 Permission Ticket の発行を認可サーバから取得する必要があるのでそれを取得しにいく。
CAP1 は上記リクエストから RP1 が必要とするコンテキストとそのスコープを判断し、適切な Permission Ticket 取得要求を行う。
CAP1 は次のようなHTTP要求を認可サーバに送信する。
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

これを受けて、認可サーバは Permission Ticket を発行する。
CAP1 は発行された Permission Ticket を RP1 へ送信し、認可サーバから RPT トークンを取得するように要求する。
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: UMA realm="cap1.ztf-proto.k3.ipv6.mobi",
  as_uri="http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/context-share",
  ticket="eyJhYYYYYYYYYYYYYYYYYYY"
```

RP1 はユーザの登録に失敗したことを理解する。
失敗の理由が認可を受けていないことだと HTTP Status Code から判断できるので、 RP1 は認可サーバに対してトークン発行要求を行う。
Authorization ヘッダには通常の OAuth2.0 Client Credential Grant Flow でのトークン要求と同じくクライアントクレデンシャルを設定する。
Grant Type は UMA 認可であることを示す `urn:ietf:params:oauth:grant-type:uma-ticket` を設定し、
`ticket`パラメータに先ほど CAP1 から取得した Permission Ticket を設定する。
また、Requesting Party の情報として rp1 の Context-Share-IdP が発行した IDToken を `claim_token` パラメータに設定している。
```http
POST /auth/realms/context-share/protocol/openid-connect/token HTTP/1.1
Host: idp.ztf-proto.k3.ipv6.mobi
Authorization: Basic cnAxOnJwMV9zZWNyZXRfZm9yX2NvbnRleHRfc2hhcmVfaWRw
grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
&ticket=eyJhYYYYYYYYYYYYYYYYYYY
&claim_token=eyJZZZZZZZZZZZZZZZZZZZZZ
&claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken
```

認可サーバはこれら要求から RPT トークンを発行していいか判断する。
しかし、ユーザはまだ RP1 に関するポリシーを設定していないため判断することができない。
認可サーバは認可を下すためにはユーザのポリシー設定が必要だと判断し、エラーを返す。
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{  
   "error": "access_denied",
   "error_description":"request_submitted",
}
```

RP1 はユーザのポリシー設定がコンテキスト取得に必要だとエラーメッセージから判断し、そのことをエラーとしてユーザに伝える。
![RP1 はコンテキスト取得にはポリシー設定が必要だと知る](assets/rp1_ctx_req_submitted.png)

# 2. ユーザは認可サーバにポリシーを設定する
ユーザは認可サーバで RP1 が CAP1 からコンテキスト取得することを許可するために、ポリシーを設定する。

今回は、 Keycloak 組み込みのポリシー設定を使う。
Keycloak はリソースごとに Requesting Party の要求を承認するか、拒否するか選択できる。
さらに、承認する場合は要求のうち承認するスコープを制限することができる。

ポリシー設定画面は次。
![認可サーバでのポリシー設定](assets/idp_policy_set.png)
今回は、コンテキスト識別子 `ctx-1` については `scope1` だけ承認することにした。
また、コンテキスト識別子 `ctx-2` については全て承認することにした。

# 3. RP1 は CAP1 からコンテキストを取得する
ポリシーの設定が終われば、ユーザは RP1 に再びアクセスを試みる。
アクセス要求を受けた RP1 は同様に CAP1 に対してユーザ登録を行う。

ユーザ登録をする前に RP1 は認可サーバから RPT トークンを取得しにいく。
前述のものと同じHTTP要求を認可サーバに行うと、今度はポリシーの設定が完了していたため認可サーバは認可判断を下すことができる。
下した判断を RPT トークンとして RP1 へ応答する。
応答は通常の OAuth2.0 と同じ形式である。

RPT トークンを取得した RP1 はユーザ登録要求を CAP1 に対して行う。
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

ユーザ登録要求を受けた CAP1 は Authorization ヘッダに RPT があることを確認し、そのトークンの検証を行う。
検証に成功すれば、ユーザの登録を行う。
トークンに記述してある通り、 `ctx-1` を `scope1` に制限した状態でユーザを登録する。

CAP1 は新しくユーザの登録が行われたと判断すると、その登録を行った RP に対してコンテキストを提供する。
例えば、 CAP1 は次のような[SET](https://tools.ietf.org/html/rfc8417) を RP1 へ送信する。
```HTTP
POST /auth/pip/ctx/0/recv HTTP/1.1
HOST: rp1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoic2NvcGUxOnZhbHVlIn19fX0.
SiGV0pK3rF3CAUrGABqvyHrP-zYE9zOrBNQdMBW9TPw
```
jwt ペイロードをデコードしてみると次のようになる。
ユーザが制御した通り、`ctx-1` については `scope1` の値のみ送信している。
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

こうして、 RP1 は CAP1 からこのユーザに関するコンテキストを取得できる。
取得したコンテキストに従って、 RP1 のアクセス制御部はユーザのアクセス可否を判断できる。
RP1 のログを見てみると、次のような情報に基づいてアクセス可否を判断していることがわかる。
上述の通り、 `ctx-1` については `scope1` の情報のみで、 `ctx-2` については要求した全てのスコープの情報を扱えている。
```
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): scope1:value
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value
```

# 4. CAP のエージェントはコンテキストの更新を検知し、それを CAP へ伝える
CAP のエージェントを簡単なプログラムで構成している。このエージェントは実行すると次のHTTP要求を CAP1 へ送信する。
```HTTP
POST /ctx/recv HTTP/1.1
HOST: cap1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiY2FwMSJdLCJpc3MiOiJjYXAxLWFnZW50IiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEiLCJzY29wZTIiOiJuZXd3d3d3d3d3d3ctdmFsdWVlZWVlISEhISJ9fX19.
XWS3y5QvX1CTYuc5CWvgwOvIOtgOJSIqSadzdXayYmQ
```
body にある jwt ペイロードをデコードしてみると次のようになる。
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
このエージェントは `ctx-1` が新しい値になったことを知らせている。
このコンテキストの更新を受け取った CAP1 は管理しているコンテキストを更新する。

# 5. RP1はCAPを介して更新されたコンテキストを共有する
CAP1 はエージェントからコンテキストの更新を受け取るとそれを必要な RP に対して通知する。
今回は、このユーザの `ctx-1` に対して RP1 がコンテキストの更新通知を要求しているので、 RP1 に対して次のようなHTTP要求を送信する。
```http
POST /auth/pip/ctx/0/recv HTTP/1.1
HOST: rp1.ztf-proto.k3.ipv6.mobi
Content-Type: application/secevent+jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMTAzMiwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEifX19fQ.
sVL7FkA3eLgxQ7yUvvmuk3P2TiD1UfR_congU2RXiRE
```
body の jwtペイロードを見てみると次のようになる。
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
確かに、コンテキストの更新が反映されていることが確認できる。
さらに、ユーザの制御に従って提供されるコンテキストが制限されていることも確認できる。

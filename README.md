# ZTF-Protptype
研究の PoC として作成したプロトタイプ。

## 過去のバージョン
- DICOMO2020: [branch](https://github.com/hatake5051/ztf-prototype/tree/dicomo2020)


## How To Run
この例は一つの物理ホスト上で動かすことを想定している。
また、物理ホストには `ztf-proto.k3.ipv6.mobi` というホスト名が割り振られているものとしている。
さらにDNSレコードとして `*.ztf-proto.k3.ipv6.mobi` は全て `ztf-proto.k3.ipv6.mobi` と同じIPアドレスを持つと記述してあると仮定する。

動作環境は docker を用いて構築する。

まずは docker network の作成する。
```bash
$ docker network create reverse-proxy-net
```

今回は一つの物理ホスト上に仮想のホスト(RP,IdP,CAP) を立てるため、リバースプロキシを用意する。
リバースプロキシとして設定が容易な https://github.com/nginx-proxy/nginx-proxy を利用する。
docker-compose を利用してリバースプロキシを構築する。
```bash
$ pwd
<適当なパス>/ztf-prototype/example/rever-proxy
$ docker-compose up
```
### IdP の構築
今回は IdP として Keycloak(https://www.keycloak.org/) を利用する。
同様に docker-compose を使って構築する。
```bash
$ pwd
<適当なパス>/ztf-prototype/example/idp 
$ docker-compose up
```
すると、 idp.ztf-proto.k3.ipv6.mobi でIdP(Keycloak) にアクセスできる。

IdP の構築に成功した後は、 IdP の初期設定を行う。
Keycloak は realm という機能によって identity 管理を分離できる。 realm が違えばたとえユーザ名などが同じでも同じユーザであるとは限らない。
RP ログイン用の IdP と CAP ログイン用の IdP と RP と CAP のコンテキスト共有用の IdP を異なる IdP として扱うため、 realm を３つ作る。

#### RP 用の IdP の設定
`rp1-idp` realm を作り、そこにクライアントとしてクライアントID `rp1` のものを作成する。
rp1 を confidential client に設定し、redirect url として `http://rp1.ztf-proto.k3.ipv6.mobi/auth/pip/sub/0/callback` を設定する。
自動生成された Client secret を ztf-prototype/actors/rp/cmd/conf.json の `pip.sub.rp_config.client_secret` にコピーする。
さらに、デモ用のユーザとしてalice(ユーザ名:パスワードが `alice-rp1:alice`) を作成する。

#### CAP 用の IdP の設定
`cap1-idp` realm を作り、そこにクライアントとしてクライアントID `cap1` を作る
cap1 を confidential client に設定し、 redirect url として `http://cap1.ztf-proto.k3.ipv6.mobi/oidc/callback` を設定する。
自動生成された Client secret を ztf-prototype/actors/cap/cmd/conf.json の cap.openid.rp_secret にコピーする。
さらに、デモ用のユーザとして、alice(`alice-cap1:alice`) を追加する。

#### RP と CAP のコンテキスト共有用の IdP の設定
`context-share` realm を作り、そこにクライアントとしてクライアントID `rp1` のものと `cap1` のものを作成する。
この realm の IdP は UMA 認可サーバとしても使うので、Realm Settings の General にある User-Managed Access をONに設定する。

- クライアント rp1 を設定するときは
  - service account enabled をONに設定する
      -   このクライアントは Client Credential Grant Flow を用いて UMA の Requesting Party Token を取得しにいくため
  - confidential client に設定し、 redirect url として `http://rp1.ztf-proto.k3.ipv6.mobi/auth/pip/ctx/0/callback` を設定する
  - 自動生成された Client secret を ztf-prototype/actors/rp/cmd/conf.json の 次の箇所にコピーする
    - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".authN.rp_config.client-secret`
    - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".recv.oauth2.client-secret`
    - `pip.ctx.cap_to_rp."http://cap1.ztf-proto.k3.ipv6.mobi".recv.uma.client_credential.secret`
- クライアント cap1 を設定するときは
  - authorization enabled をONに設定する
    - このクライアントは UMA Resource Server として機能するため
  - service account enabled をONに設定する
    - このクライアントは Client Credential Grant Flow を用いて UMA の Protection API Token を取得しにいくため
  - confidential client に設定し、 redirect url として `http://cap1.ztf-proto.k3.ipv6.mobi/uma/oidc/callback` を設定する
  - Authorization 設定タグの Resources タグに Default Resource があるのでそれを削除しておく。
    - デフォルトの認可判断ポリシー設定は不要なため
  - 自動生成された Client Secret を ztf-prototype/actors/cap/cmd/conf.json の次の箇所にコピーする
    - `uma.client_secret`
    - `caep.openid.rp_secret`
  
次のユーザ登録を行う
- RP1 (`rp1:rp1`)をユーザとして追加する
  -  Requesting Party として UMA RPT を取得しにいくため
     -  Keycloak では UMA Grant Flow に必ず Requsting Party のユーザ情報が認可判断時にあるものとして設計されているため
- デモ用のユーザとして、 alice(`alice-rp1:alice`) を追加する

### CAP と RP の構築
CAP と RP を docker-compose を使って構築する
```bash
$ pwd
<適当なパス>/ztf-prototype/example/cap
$ docker-compose up
```

```bash
$ pwd
<適当なパス>/ztf-prototype/example/rp
$ docker-compose up
```

これで環境構築は終了。

## プロトタイプのユースケース
前提として、ユーザは RP1 のサービスにアクセスしたいと考えている。
また、RP1 はユーザのアクセス制御のために CAP1 からコンテキスト提供を受けたいと考えている。

事前準備として、ユーザは CAP1 にログインしてコンテキストの管理を IdP(context-share realm) のUMA-enabled な認可サーバにまかせたいと考え、それを実行する。
まず、ユーザは CAP1 にアクセスする。
まだ、 CAP1に対してログインをしていなかったので、 IdP(cap1-idp realm) にリダイレクトが行われる。
必要なクレデンシャル(alice-cap1:alice) を入力してログイン

ログインすると、次のような画面が現れる。
コンテキストを UMA で管理したいため、「コンテキストを管理する」をクリック。
UMA Protection API で CAP1 にある自身のコンテキストを「リソース」として認可サーバ(context-share realm)に登録する。
context-share realm の identity を使ってリソースを登録するため、 context-share realm で認証を行う。
リソース登録画面は次。まだリソース登録を済ましていないことがわかる。

一つずつ登録を行う。登録が終わると、「リソース」として登録したコンテキストの詳細を確認できる。
例えば、CAP1 が管理しているコンテキスト「ctx-1」をユーザ alice-share が認可サーバに登録すると次のような情報が得られる。
また、UMA認可サーバでリソースが管理されていることを確認することができる。

ここまでで、CAP のコンテキストをUMA 認可サーバに登録することができた。これによって CAP のコンテキストをUMAで管理することができる。

それでは、RP1へアクセスを行う。
まだ、ユーザは RP1 へログインしていなかったので、IdP(rp1-idp realm) で認証を行う。
認証が同じ RP1 がユーザを識別できた後は、認可判断を行う。
認可判断のためにはコンテキストが必要で、今回は CAP の提供するコンテキスト ctx-1 と ctx-2 を使うとポリシーを設定していたとする。
コンテキストの提供を CAP から受けるために、 context-share の identity を求める

コンテキストの取得を CAP から受けたかったが、まだユーザはこの RP1 に対して認可を与えるポリシーを設定していないので、そのエラーを表示する。

そこで、ユーザは認可サーバに赴き、ポリシーの設定を行う。
RP1が要求しているコンテキストとそのスコープが表示されている。今回は、 sub:alice-share:ctx:ctx-1 の scope2 は承認せず、 scope1 だけ承認するようにしてみる。
また、 ctx-2 は全て承認する。

ユーザはRP1に戻り、アクセスを試みる。すると、コンテキストの提供の承認を与えているためクリアしてアクセスができた。


認可判断に使われたコンテキストのログを見てみると、確かに ctx-1 については scope1 のみ提供されている。
```
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): scope1:value
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value
```

さらに、ここで CAP の所有しているコンテキスト情報を変えてみる。
今回は、CAPがエージェントをユーザに配置していることとし、エージェントは事前にユーザの識別子を取得しているものとする。
この時、エージェントが新しいコンテキストを送信すると、CAPはコンテキストの更新を受けてそれを必要なRPへ提供する。
RP1はその提供を受ける。
よって、ユーザがRP１にアクセスしなおすとコンテキスト情報が変わっていることがわかる。

```
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): new-value!!!!!
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value
```

rp1 のろぐ
```
rp_1  | 2020/11/25 18:52:46 server starting...
rp_1  | request comming with /
rp_1  | request comming with /auth/pip/sub/0/callback?session_state=82b26d17-cde1-4359-8b59-74d7ca0c3ad0&code=647489e8-b702-4ad0-a96e-f03f5ad62331.82b26d17-cde1-4359-8b59-74d7ca0c3ad0.ef4d904d-c342-40b5-a12a-fb2d35931e35
rp_1  | request comming with /
rp_1  | pdp.NotifiedRequest start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) without context
rp_1  | request comming with /auth/pip/ctx/0/callback?session_state=806883e4-b6bb-414b-841d-173e357b2290&code=7cae2756-7d07-490a-8e1f-a252629e6f75.806883e4-b6bb-414b-841d-173e357b2290.8d8554b2-511c-4388-9df9-d2bd65b50d95
rp_1  | request comming with /
rp_1  | pdp.NotifiedRequest start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) without context
rp_1  | request comming with /
rp_1  | pdp.NotifiedRequest start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) without context
rp_1  | request comming with /auth/pip/ctx/0/recv
rp_1  | caeprecv spagid:26ba8184-895f-420d-8591-611784805fe3 context:&{ctx-1 map[scope1:scope1:value]}
rp_1  | request comming with /auth/pip/ctx/0/recv
rp_1  | caeprecv spagid:26ba8184-895f-420d-8591-611784805fe3 context:&{ctx-2 map[scope111:scope111:value scope2:scope2:value]}
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): scope1:value
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value
rp_1  | request comming with /auth/pip/ctx/0/recv
rp_1  | caeprecv spagid:26ba8184-895f-420d-8591-611784805fe3 context:&{ctx-1 map[scope1:new-value!!!!!]}
rp_1  | request comming with /
rp_1  | pdp.NotifiedRequest start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) without context
rp_1  | pdp.Decision start...
rp_1  | sub(984d4f1d-6c4f-4829-9188-f90b9d5ccddd) wants to do action(dummy-action) on res(dummy-res) with context
rp_1  |   ctx(ctx-1)
rp_1  |     scope(scope1): new-value!!!!!
rp_1  |   ctx(ctx-2)
rp_1  |     scope(scope111): scope111:value
rp_1  |     scope(scope2): scope2:value

```

cap のろぐ
```
cap_1  | 署名したよ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoic2NvcGUxOnZhbHVlIn19fX0.SiGV0pK3rF3CAUrGABqvyHrP-zYE9zOrBNQdMBW9TPw
cap_1  | 送信に成功 recv: {rp1 http://rp1.ztf-proto.k3.ipv6.mobi 0xc0000bd0e0} -> set: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoic2NvcGUxOnZhbHVlIn19fX0.SiGV0pK3rF3CAUrGABqvyHrP-zYE9zOrBNQdMBW9TPw
cap_1  | 署名したよ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0yIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxMTEiOiJzY29wZTExMTp2YWx1ZSIsInNjb3BlMiI6InNjb3BlMjp2YWx1ZSJ9fX19.EEnj98-ZN1Rzk9lykg7ZIrRGl7SsKYztQLn3vBeM88M
cap_1  | 送信に成功 recv: {rp1 http://rp1.ztf-proto.k3.ipv6.mobi 0xc0000bd0e0} -> set: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMDc5MCwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0yIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxMTEiOiJzY29wZTExMTp2YWx1ZSIsInNjb3BlMiI6InNjb3BlMjp2YWx1ZSJ9fX19.EEnj98-ZN1Rzk9lykg7ZIrRGl7SsKYztQLn3vBeM88M
cap_1  | 新しいコンテキストを受け取った &{ctx-1 {spag 26ba8184-895f-420d-8591-611784805fe3} map[scope1:new-value!!!!! scope2:newwwwwwwwww-valueeeee!!!!]}
cap_1  | 署名したよ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMTAzMiwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEifX19fQ.sVL7FkA3eLgxQ7yUvvmuk3P2TiD1UfR_congU2RXiRE
cap_1  | 送信に成功 recv: {rp1 http://rp1.ztf-proto.k3.ipv6.mobi 0xc0000bd0e0} -> set: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiaHR0cDovL3JwMS56dGYtcHJvdG8uazMuaXB2Ni5tb2JpIl0sImlhdCI6MTYwNjMzMTAzMiwiaXNzIjoiaHR0cDovL2NhcDEuenRmLXByb3RvLmszLmlwdjYubW9iaSIsImp0aSI6Im1ldHlha3V0eWEtcmFuZG9tIiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEifX19fQ.sVL7FkA3eLgxQ7yUvvmuk3P2TiD1UfR_congU2RXiRE
```

agent のろぐ
```
送信に成功  set: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiY2FwMSJdLCJpc3MiOiJjYXAxLWFnZW50IiwiZXZlbnRzIjp7ImN0eC0xIjp7InN1YmplY3QiOnsic3ViamVjdF90eXBlIjoic3BhZyIsInNwYWdfaWQiOiIyNmJhODE4NC04OTVmLTQyMGQtODU5MS02MTE3ODQ4MDVmZTMifSwicHJvcGVydHkiOnsic2NvcGUxIjoibmV3LXZhbHVlISEhISEiLCJzY29wZTIiOiJuZXd3d3d3d3d3d3ctdmFsdWVlZWVlISEhISJ9fX19.XWS3y5QvX1CTYuc5CWvgwOvIOtgOJSIqSadzdXayYmQ
```
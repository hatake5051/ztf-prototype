# ZTF-Protptype
研究の PoC として作成したプロトタイプ。

## 過去のバージョン
- DICOMO2020: [branch](https://github.com/hatake5051/ztf-prototype/tree/dicomo2020)

## プロトタイプのユースケースの動作例はこちら
https://github.com/hatake5051/ztf-prototype/blob/master/example/usecase.md

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

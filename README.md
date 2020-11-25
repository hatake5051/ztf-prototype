# ZTF-Protptype
研究の PoC として作成したプロトタイプ。

## 過去のバージョン
- DICOMO2020: [branch](https://github.com/hatake5051/ztf-prototype/tree/dicomo2020)


## exampleの動かし方
まずは docker network の作成とDNSの設定を行う
```bash
$ docker network create reverse-proxy-net
```

ホストファイルに example.com の名前解決を書いておく

そしたら、リバースプロキシを up
```
$ pwd
<適当なパス>/example/rever-proxy
$ docker-compose up
```

次に、 IdP を up
```
$ pwd
<適当なパス>/example/idp
$ docker-compose up
```

そうすると idp.example.com でIdP(Keycloak) にアクセスできる

realm を作る
rp1-idp realm を作り、そこにクライアントとして rp1 を作る

context-share realm を作り、そこにクライアントとして rp1 cap1 を作る
realm setting の UMA をおんに
rp1 のときは service account enabled を on に
cap1 のときはservice account enabled を on に authorization enabled を on に

それぞれの realm に alice:alice のアカウントを作っておく

CAP を up
```
$ pwd
<>/example/cap
$ docker-compose up
```
# ユースケース
今回は次のようなプロトタイプを作成・実行し、コンテキストの共有が行えていることを確認した。
CAP、RP1、RP2、IdPの4つの entityとユーザがいる状況において、次のユースケースを考える。

1. ユーザはRP1にアクセスする
1. ユーザはRP2にアクセスする
1. ユーザはRP1の管理下でコンテキストを更新する
1. RP2はCAPを介して更新されたコンテキストを共有する

このシナリオにより、RP2がZTFに参加していなれば認識できないコンテキストをユーザの同意のもと共有できていることを、実際にやりとりされるHTTPのメッセージとともに示す。

まず、ユーザはRP1にアクセスする。
```HTTP
GET /access HTTP/1.1
Host: rp1.demo
```

するとRP1はコンテキストの共有プロセスの開始要求を返す。
RP1はユーザから承諾を受けるとCAPからコンテキストを取得するためのチャネルの開通を目指す。
```HTTP
GET /register HTTP/1.1
HOST: rp1.demo
```
そのためにはCAPからチャネル確立のためのアクセストークンが必要なため、RP1はOAuth2.0フローを開始する。
その際、提供されたいコンテキストをOAuth2.0のスコープとして表現する。
今回は
- `device:useragent:raw`
- `device:useragent:predicate:recentlyused`
- `user:location:raw+user:location:predicate:recentlystayed`
- `user:location:predicate:isjapan`

の４つのコンテキストをCAPに要求する。
```HTTP
HTTP/1.1 302 Found
Location: http://cap.demo:80/authorize?client_id=rp1&redirect_uri=http%3A%2F%2Frp1.demo%3A80%2Fcallback&response_type=code&scope=device%3Auseragent%3Araw+device%3Auseragent%3Apredicate%3Arecentlyused+user%3Alocation%3Araw+user%3Alocation%3Apredicate%3Arecentlystayed+user%3Alocation%3Apredicate%3Aisjapan&state=NMcBstZfvYnU
```

しかし、RP1からのリダイレクトを受けたCAPはユーザのIDトークンを持っていないため誰のコンテキストを提供すべきかわかっていない。どのため、IdPから取得しようとOpenID Connectフローを開始する。
```HTTP
HTTP/1.1 302 Found
Location: http://idp.demo:80/authenticate?client_id=cap&redirect_uri=http%3A%2F%2Fcap.demo%3A80%2Fcallback&response_type=code&scope=openid&state=SJUpzefcrNWu
```

CAPからのリダイレクトを受けたIdPはユーザの認証を行い、認証に成功すればCAPへコールバックする。今回はOpenID Connect Authentication using Authorization Code Grant Flowに従うため、IDトークンそれ自体ではなく、認証成功したことを示す `code` をCAPへ送信する。
```HTTP
HTTP/1.1 302 Found 
Location: http://cap.demo:80/callback?code=EyopFIPC&state=SJUpzefcrNWu
```

CAPはIdPからリダイレクトを受け、ユーザのIDトークン (今回は`alice`)を取得する。
```HTTP
POST /token HTTP/1.1
Host: idp.demo:80
Content-Type: application/x-www-form-urlencoded

code=EyopFIPC
&grant_type=authorization_code
&redirect_uri=http%3A%2F%2Fcap.demo%3A80%2Fcallback
```
```HTTP
HTTP/1.1 200 OK

{"access_token":"bdmizHACowOpMHewYtxnwFDrzSsdkP",
 "token_type":"Bearer",
 "scope":"openid",
 "id_token":"
  { 
    "alg": "none", 
    "typ": "JWT" 
  }.
  { "aud": "cap",
    "iss": "http://idp.demo:80",
    "sub": "alice"
  }."
}
```

CAPはIDトークンを取得すると、ユーザ(`alice`)に対してコンテキストをRP1に提供して良いかについての同意を要求する。

![同意画面](./images/demo-cap-consent.png)

```HTTP
POST /approve HTTP/1.1
Host: cap.demo
Content-Type: application/x-www-form-urlencoded

approve=Approve
&scope_device%3Auseragent%3Araw=on
&scope_device%3Auseragent%3Apredicate%3Arecentlyused=on
&scope_user%3Alocation%3Araw=on
&scope_user%3Alocation%3Apredicate%3Arecentlystayed=on
&scope_user%3Alocation%3Apredicate%3Aisjapan=on
```
今回は全てに同意する。
すると、CAPは同意を受けた事実をRP1へリダイレクトを介して通知する。
```HTTP
HTTP/1.1 302 Found
Location: http://rp1.demo:80/callback?code=awKwSEik&state=NMcBstZfvYnU
```

RP1はCAPからアクセストークンを取得する。
```HTTP
POST /token HTTP/1.1
Host: cap.demo:80
Content-Type: application/x-www-form-urlencoded

code=awKwSEik
&grant_type=authorization_code
&redirect_uri=http%3A%2F%2Frp1.demo%3A80%2Fcallback
```
```HTTP
HTTP/1.1 200 OK
Content-Type: application/json

{ "access_token":"DhjNmEQKTTbIdcNUgNlgpiahnTzjTG",
  "token_type":"Bearer",
  "scope":"device:useragent:raw device:useragent:predicate:recentlyused user:location:raw  user:location:predicate:recentlystayed user:location:predicate:isjapan"
}
```

RP1はアクセストークンを取得した。
つまり、RP1がCAPからコンテキストを取得することについてユーザから同意を取ることができている。
よって、RP1はCAPにコンテキスト取得のためのサブスクライブの登録を要求する。
```HTTP
POST /registersubsc HTTP/1.1
Host: cap.demo:80
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer DhjNmEQKTTbIdcNUgNlgpiahnTzjTG

url=http%3A%2F%2Frp1.demo%3A80%2Fsubscribe
```

登録要求を受けるにあたって、CAPはRP1に対する同意を確認する。
確認はAuthorizationヘッダにある認可付与トークンを検証することでわかる。今回はCAPが自身の認可検証ポイントに問うている。
```HTTP
POST /introspect HTTP/1.1
Host: cap.demo:80 
Content-Type: application/x-www-form-urlencoded
token=lLyuSgppORekaCLWJBkBsLaUWlUYzV
```
```HTTP
HTTP/1.1 200 OK
{"active": true,
 "username": "alice",
 "scope": "device:useragent:raw device:useragent:predicate:recentlyused user:location:raw  user:location:predicate:recentlystayed  user:location:predicate:isjapan",
 "iss": "http://cap.demo:80",
 "aud": "http://cap.demo:80"
}
```

全て同意した通り、RP1は要求した全てのコンテキストを取得することが認められている。
登録に成功すると、CAPはRP1に対してコンテキストの提供を始める。
ただし、未だ誰もCAPに対してコンテキストの提供を行っていないため、コンテキストの中身はない。
```HTTP
POST /subscribe HTTP/1.1
Host: rp1.demo:80
Content-Type: application/jwt

{ "alg": "none", "typ": "JWT" }.
{ "aud": "http://rp1.demo:80/subscribe",
  "iss": "http://cap.demo:80",
  "sub": "alice",
  "events": {
    "device:useragent:predicate:recentlyused": false,
    "device:useragent:raw": null,
    "user:location:predicate:isjapan": false,
    "user:location:predicate:recentlystayed": false,
    "user:location:raw": null
  }
}.
```

次に、RP1はCAPへコンテキストを提供することについて同意を取る。

![同意画面](./images/demo-rp-consent.png)

次に、RP2に対しても同様のことを行い、RP2とCAPの共有について同意しておく。
ただし、RP2に対してユーザはロケーションが日本かどうかという条件式を使うpredicateレベルにコンテキストを制限しておく。

![同意画面](./images/demo-cap-rp2-consent.png)

RP1にアクセスを再開した際、RP1がコンテキストの変更を発見したとする。
すると、RP1はCAPに対してそのことを共有する。
```HTTP
POST /collect HTTP/1.1
Host: cap.demo:80
Content-Type: application/jwt

{ "alg": "none", "typ": "JWT" }.
{ "aud": "http://cap.demo:80/collect",
  "iss": "http://rp1.demo:80/",
  "sub": "alice",
  "events": {
    "device:useragent:raw": "newdevice",
    "user:location:raw": "ja"
  }
}
```

CAPは共有を受け、コンテキストを蓄積する。
さらに、このコンテキストの更新をサブスクライブしているRPに対して共有も行う。
```HTTP
POST /subscribe HTTP/1.1
Host: rp2.demo:80
Content-Type: application/jwt

{ "alg": "none", "typ": "JWT" }.
{ "aud": "http://rp2.demo:80/subscribe",
  "iss": "http://cap.demo:80",
  "sub": "alice",
  "events": {
    "user:location:predicate:isjapan": true
  }
}
```

今回であれば、RP2がコンテキストのうちロケーションが日本であるかについてのみ共有することを認められているため、
コンテキストとして1つだけ共有されている。ロケーションに関する生の情報やuseragentに関する情報は提供されない。

このように、提案システムはZTF下でコンテキストの共有ができている。
さらに、コンテキストの共有をユーザの制御下に置くことができている。

# Publish
- [DICOMO2020](https://github.com/hatake5051/ztf-prototype/tree/v1.0)

# 実行の仕方
デフォルトではconf.envには存在しないドメイン名を書いているため、hostsファイルなどに名前解決用の記述を追加。
例えば、
```
# macだと /private/etc/hosts
# for sotsuron demo
127.100.0.1 idp.demo
127.200.0.1 cap.demo
127.255.10.1 rp1.demo
127.255.20.1 rp2.demo
```
この場合だと、loopbackアドレスを使っているので、`lo0`インターフェースに色々エイリアスを用意しておく。
```bash
$ ifconfig lo0
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
        inet6 ::1 prefixlen 128 
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
        inet 127.100.0.1 netmask 0xff000000 
        inet 127.200.0.1 netmask 0xff000000 
        inet 127.255.10.1 netmask 0xff000000 
        inet 127.255.20.1 netmask 0xff000000 
        nd6 options=201<PERFORMNUD,DAD>
```
エイリアスの貼り方は
```bash
$ ifconfig lo0 alias 127.100.0.1 netmask 0xff000000
```

すると、ルーティングはうまく行くのであとは、実行するだけ。
まずはgoプログラムをビルド
```bash
$ go build main.go
```
conf.envをきちんと環境変数に
```bash
$ export $(cat conf.env)
```
`localhost`以外のIPを使っているので(?)、プログラムは`sudo`で動かす。
```bash
$ sudo -E main
```
`-E`オプションは、環境変数を引き継ぐため。

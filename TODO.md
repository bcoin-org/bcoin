# Todo

Todo before release. Excuse the mess.

- prioritization for mining.
- switch entirely to secp256k1-node. note that payment-protocol still directly
  requires elliptic.
- walletdb removes coins from txs - potentially have it clone the tx (slower).
- refactor and add all network packets.
- rename keyring object.
- browser-side dsa signing/verify for payment-protocol.
- do not output bitcoin strings (utils.btc) on the api layer. use satoshis
  instead.
- implement jl's latest MAST.
- rewrite readme. move examples to wiki.
- fix docs.
- implement rpc calls:
  - listaddressgroupings
  - importaddress (maybe)
- man pages

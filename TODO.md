# Todo

Todo before release. Excuse the mess.

- prioritization for mining.
- switch entirely to secp256k1-node. bad for payment-protocol and ec.random
  (add crypto/random.js).
- walletdb removes coins from txs - potentially have it clone the tx (slower).
- move siphash to utils?
- refactor and add all network packets.
- rename keyring object.
- browser-side dsa signing/verify for payment-protocol.
- add preliminary support for schnorr and bls signatures.
- potentially rewrite walletdb to avoid O(n) complexity for tx insertion to
  multiple wallets (n=number-of-wallets-mapped: 1 in the average case, 2 in
  average worst case, potentially thousands in bullshit worst case). doing
  this, we would lose fast iteration over txs, coins, and undo coins.
- do not output bitcoin strings (utils.btc) on the api layer. use satoshis
  instead.
- upgrade to leveldb 1.19.
- bindings to asm chacha20+poly1305.
- bindings to asm sha256 (use webgl shader in browser).
- implement jl's latest MAST.
- rewrite readme. move examples to wiki.
- fix docs.
- implement rpc calls:
  - backupwallet
  - listaddressgroupings
  - importaddress (maybe)
- rename cost to weight.

Wallet REST API: [REST-RPC-API](REST-RPC-API.md)

## Notes on wallet system

Bcoin maintains a wallet database which contains every wallet. Wallets are _not
usable_ without also using a wallet database. For testing, the wallet database
can be in-memory, but it must be there.

Wallets in bcoin use bip44. They also originally supported bip45 for multisig,
but support was removed to reduce code complexity, and also because bip45
doesn't seem to add any benefit in practice.

The wallet database can contain many different wallets, with many different
accounts, with many different addresses for each account. Bcoin should
theoretically be able to scale to hundreds of thousands of
wallets/accounts/addresses.

Each account can be of a different type. You could have a pubkeyhash account,
as well as a multisig account, a witness pubkeyhash account, etc.

Note that accounts should not be accessed directly from the public API. They do
not have locks which can lead to race conditions during writes.

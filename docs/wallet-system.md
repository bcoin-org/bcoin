# Wallet system

Bcoin maintains a wallet database which contains every wallet. Wallets are
_not usable_ without also using a wallet database. For testing, the wallet
database can be in-memory, but it must be there.

Wallets in bcoin are based on BIP44. They also originally supported BIP45 for
multisig, but support was removed to reduce code complexity, and also because
BIP45 doesn't seem to add any benefit in practice.

The wallet database can contain many wallets, with many accounts, with many
addresses for each account. Bcoin should theoretically be able to scale to
hundreds of thousands of wallets/accounts/addresses.

## Deviation from BIP44

**It's important to backup the wallet database.** There are several deviations
from [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
that break the deterministic algorithm, and therefore it's recommended to
backup the wallet database any time an account is created, as there are several
possible configurations of an account.

There is a command available via the wallet RPC called `backupwallet` that can
clone the database to a new destination. There are also the RPC calls
`dumpwallet` and `dumpprivkey` for exporting private keys. After shutting down
the wallet process, it's also possible to copy the LevelDB database from the
default location at `~/.bcoin/wallet` for main net or
`~/.bcoin/<network>/wallet` for others. Copying LevelDB while the process is
running can result in a corrupted copy. LevelDB is also prone to
[database corruption](https://en.wikipedia.org/wiki/LevelDB#Bugs_and_reliability).

Each account can be of a different type. You could have a pubkeyhash account,
a multisig account, and a witness pubkeyhash account all in the same wallet.
Accounts can be configured with or without Segregated Witness and both base58
(nested-in-P2SH) and bech32 (native) P2WPKH addresses can be derived from the
same account.

Bcoin adds a third branch to each account for nested SegWit addresses.
Branch `0` and `1` are for `receive` and `change` addresses respectively
(which is BIP44 standard) but branch `2` is used by bcoin to derive
[nested SegWit addresses.](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#P2WPKH_nested_in_BIP16_P2SH)

Accounts in a bcoin wallet can be configured for multisig and import xpubs
from cosigners. Externally-generated Extended Private Keys (`xpriv`) and non-HD
single address private keys can all be imported into a bcoin wallet. Balances
of those addresses can be watched as well spent from (in the case of a private
key).

Unlike [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki),
bcoin does not limit account depth and a new account can be created
after an empty account. This can create issues with deterministic account
discovery from the master node (seed) as there are `2 ^ 31 - 1` _(worst case)_
possible accounts to search.

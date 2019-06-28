# RPC Updates to the bcoin

## Ports
Bitcoin Core does not separate wallet and node:

| Network | Bcoin Node RPC | Bcoin Wallet RPC | Bitcoin Core (Wallet & Node)|
| ---     | ---            | ---              | ---         |
| Main    | 8332           | 8334             | 8332        |
| Testnet | 18332          | 18334            | 18332       |
| Regtest | 48332          | 48334            | 18443       |

# List of RPC Calls in Bitcoin Core vs Bcoin
This is a list of commands existing in core and bcoin.  
This list currently does not include compatibility information.

Note: zmq is separate from bcoin, see [bzmq](https://github.com/bcoin-org/bzmq/).

## Node RPC calls

### Server - control
These are same for wallet and the node.

| RPC Method   | Bcoin              | Core                                                  | Compatible |
| ----         | ----               | ----                                                  | ----       |
| `getrpcinfo` | `-`                | :heavy_check_mark: [since v0.18] [PR][new-getrpcinfo] | :x:        |
| `help`       | :heavy_check_mark: | :heavy_check_mark:                                    | :x:        |
| `stop`       | :heavy_check_mark: | :heavy_check_mark:                                    | :question: |
| `uptime`     | `-`                | :heavy_check_mark: [since v0.15] [PR][new-uptime]     | :x:        |

[new-getrpcinfo]: https://github.com/bitcoin/bitcoin/pull/14982
[new-uptime]: https://github.com/bitcoin/bitcoin/pull/10400


### Blockchain
#### blockchain
| RPC Method              | Bcoin                         | Core                                                                  | Compatible               |
| ----                    | ----                          | ----                                                                  | ----                     |
| `getblockchaininfo`     | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getchaintxstats`       | `-`                           | :heavy_check_mark: [since v0.15] [PR][new-getchaintxstats]            | :x:                      |
| `getblockstats`         | `-`                           | :heavy_check_mark: [since v0.17] [PR][new-getblockstats]              | :x:                      |
| `getbestblockhash`      | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getblockcount`         | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getblock`              | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getblockbyheight`      | :heavy_check_mark:            | `-` [never]                                                           | :x:                      |
| `getblockhash`          | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getblockheader`        | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getchaintips`          | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getdifficulty`         | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getmempoolancestors`   | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getmempooldescendants` | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getmempoolentry`       | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getmempoolinfo`        | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `getrawmempool`         | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `gettxout`              | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `gettxoutsetinfo`       | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `pruneblockchain`       | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `savemempool`           | `-`                           | :heavy_check_mark: [since v0.16] [PR][new-savemempool]                | :x:                      |
| `verifychain`           | :heavy_check_mark:            | :heavy_check_mark:                                                    | :question:               |
| `preciousblock`         | `-`                           | :heavy_check_mark: [since v0.14] [PR][new-preciousblock]              | :x:                      |
| `scantxoutset`          | `-`                           | :heavy_check_mark: [exprimental] [since v0.17] [PR][new-scantxoutset] | :x:                      |
| `getblockfilter`        | `-` [PR][bnew-getblockfilter] | :heavy_check_mark: [PR][new-getblockfilter]                           | :hourglass_flowing_sand: |

#### Hidden
| RPC Method                         | Bcoin              | Core                                                 | Compatible |
| ----                               | ----               | ----                                                 | ----       |
| `invalidateblock`                  | :heavy_check_mark: | :heavy_check_mark:                                   | :question: |
| `reconsiderblock`                  | :heavy_check_mark: | :heavy_check_mark:                                   | :question: |
| `waitfornewblock`                  | `-`                | :heavy_check_mark: [tests] [PR][new-waitfornewblock] | :x:        |
| `waitforblock`                     | `-`                | :heavy_check_mark: [tests] [PR][new-waitfornewblock] | :x:        |
| `waitforblockheight`               | `-`                | :heavy_check_mark: [tests] [PR][new-waitfornewblock] | :x:        |
| `syncwithvalidationinterfacequeue` | `-`                | :heavy_check_mark: [tests] [PR][new-swviq]           | :x:        |

[new-getchaintxstats]: https://github.com/bitcoin/bitcoin/pull/9733
[new-getblockstats]: https://github.com/bitcoin/bitcoin/pull/10757
[new-savemempool]: https://github.com/bitcoin/bitcoin/pull/11099
[new-preciousblock]: https://github.com/bitcoin/bitcoin/pull/6996
[new-scantxoutset]: https://github.com/bitcoin/bitcoin/pull/12196
[new-getblockfilter]: https://github.com/bitcoin/bitcoin/pull/14121
[bnew-getblockfilter]: https://github.com/bcoin-org/bcoin/pull/797
[new-waitfornewblock]: https://github.com/bitcoin/bitcoin/pull/8680
[new-swviq]: https://github.com/bitcoin/bitcoin/pull/12217


### Mining
| RPC Method              | Bcoin              | Core                                         | Compatible |
| ----                    | ----               | ----                                         | ----       |
| `getnetworkhashps`      | :heavy_check_mark: | :heavy_check_mark:                           | :question: |
| `getmininginfo`         | :heavy_check_mark: | :heavy_check_mark:                           | :question: |
| `prioritisetransaction` | :heavy_check_mark: | :heavy_check_mark:                           | :question: |
| `getwork`               | :heavy_check_mark: | `-` [deprecated v0.10]                       | :x:        |
| `getworklp`             | :heavy_check_mark: | `-` [never]                                  | :x:        |
| `getblocktemplate`      | :heavy_check_mark: | :heavy_check_mark:                           | :question: |
| `submitblock`           | :heavy_check_mark: | :heavy_check_mark:                           | :question: |
| `verifyblock`           | :heavy_check_mark: | `-` [never]                                  | :x:        |
| `submitheader`          | `-`                | :heavy_check_mark:                           | :question: |
| `setgenerate`           | :heavy_check_mark: | `-` [deprecated v0.13] [PR][dep-setgenerate] | :x:        |
| `getgenerate`           | :heavy_check_mark: | `-` [deprecated v0.13] [PR][dep-setgenerate] | :x:        |
| `generate`              | :heavy_check_mark: | `-` [deprecated v0.18] [PR][dep-generate]    | :x:        |
| `generatetoaddress`     | :heavy_check_mark: | :heavy_check_mark: [generating]              | :question: |

#### Util
| RPC Method              | Bcoin              | Core                                              | Compatible |
| ----                    | ----               | ----                                              | ----       |
| `estimatefee`           | :heavy_check_mark: | `-` [deprecated v0.16] [PR][dep-estimatefee]      | :x:        |
| `estimatepriority`      | :heavy_check_mark: | `-` [deprecated v0.15] [PR][dep-estimatepriority] | :x:        |
| `estimatesmartpriority` | :heavy_check_mark: | `-` [deprecated v0.15] [PR][dep-estimatepriority] | :x:        |
| `estimatesmartfee`      | :heavy_check_mark: | :heavy_check_mark:                                | :question: |

#### Hidden
| RPC Method       | Bcoin | Core                          | Compatible |
| ----             | ----  | ----                          | ----       |
| `estimaterawfee` | `-`   | :heavy_check_mark: [unstable] | :x:        |

[dep-setgenerate]: https://github.com/bitcoin/bitcoin/pull/7507
[dep-generate]: https://github.com/bitcoin/bitcoin/pull/14468
[dep-estimatefee]: https://github.com/bitcoin/bitcoin/pull/11031
[dep-estimatepriority]: https://github.com/bitcoin/bitcoin/pull/9602

### Misc
#### Control
| RPC Method      | Bcoin              | Core                                                          | Compatible |
| ----            | ----               | ----                                                          | ----       |
| `getinfo`       | :heavy_check_mark: | `-` [control] [simulate] [deprecated v0.14] [PR][dep-getinfo] | :x:        |
| `getmemoryinfo` | :heavy_check_mark: | :heavy_check_mark: [control]                                  | :question: |

#### Util
| RPC Method               | Bcoin                                         | Core                                                        | Compatible               |
| ----                     | ----                                          | ----                                                        | ----                     |
| `logging`                | :heavy_check_mark: `setloglevel`              | :heavy_check_mark:                                          | :x:                      |
| `validateaddress`        | :heavy_check_mark:                            | :heavy_check_mark:                                          | :question:               |
| `createmultisig`         | :heavy_check_mark:                            | :heavy_check_mark:                                          | :question:               |
| `createwitnessaddress`   | :heavy_check_mark:                            | `-` [deprecated v0.13.1] [PR][dep-createwitnessaddress]     | :x:                      |
| `deriveaddresses`        | `-`                                           | :heavy_check_mark: [since v0.18] [PR][new-deriveaddresses]  | :x:                      |
| `getdescriptorinfo`      | `-`                                           | :heavy_check_mark: [output descriptors][output-descriptors] | :x:                      |
| `signmessage`            | :heavy_check_mark:                            | `-` [deprecated v0.16]                                      | :x:                      |
| `verifymesage`           | :heavy_check_mark: [fix PR][bfix-signmessage] | :heavy_check_mark:                                          | :hourglass_flowing_sand: |
| `signmessagewithprivkey` | :heavy_check_mark: [fix PR][bfix-signmessage] | :heavy_check_mark:                                          | :hourglass_flowing_sand: |

#### Hidden
| RPC Method    | Bcoin              | Core                              | Compatible |
| ----          | ----               | ----                              | ----       |
| `setmocktime` | :heavy_check_mark: | :heavy_check_mark: [regtest only] | :x:        |
| `echo`        | `-`                | :heavy_check_mark:                | :x:        |
| `echojson`    | `-`                | :heavy_check_mark:                | :x:        |

[dep-getinfo]: https://github.com/bitcoin/bitcoin/pull/8780
[dep-createwitnessaddress]: https://github.com/bitcoin/bitcoin/pull/8699
[new-deriveaddresses]: https://github.com/bitcoin/bitcoin/pull/14667
[bfix-signmessage]: https://github.com/bcoin-org/bcoin/pull/802
[output-descriptors]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md

### Network
#### Network
| RPC Method           | Bcoin              | Core               | Compatible |
| ----                 | ----               | ----               | ----       |
| `getconnectioncount` | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `ping`               | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `getpeerinfo`        | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `addnode`            | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `disconnectnode`     | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `getaddednodeinfo`   | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `getnettotals`       | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `getnetworkinfo`     | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `setban`             | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `listbanned`         | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `clearbanned`        | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `setnetworkactive`   | `-`                | :heavy_check_mark: | :x:        |
| `getnodeaddresses`   | `-`                | :heavy_check_mark: | :x:        |

### Raw Transactions
#### Raw Transactions
| RPC Method                  | Bcoin               | Core                                                    | Compatible               |
| ----                        | ----                | ----                                                    | ----                     |
| `getrawtransaction`         | :heavy_check_mark:  | :heavy_check_mark:                                      | :question:               |
| `createrawtransaction`      | :heavy_check_mark:  | :heavy_check_mark:                                      | :question:               |
| `decoderawtransaction`      | :heavy_check_mark:  | :heavy_check_mark:                                      | :question:               |
| `decodescript`              | :heavy_check_mark:  | :heavy_check_mark:                                      | :question:               |
| `sendrawtransaction`        | :heavy_check_mark:  | :heavy_check_mark:                                      | :question:               |
| `signrawtransaction`        | :heavy_check_mark:  | `-` [deprecated v0.17] [PR][dep-signrawtx]              | :x:                      |
| `signrawtransactionwithkey` | `-`                 | :heavy_check_mark:                                      | :x:                      |
| `testmempoolaccept`         | `-`                 | :heavy_check_mark:                                      | :x:                      |
| `combinerawtransaction`     | `-`                 | :heavy_check_mark: [since v0.15] [PR][new-combinerawtx] | :x:                      |
| `decodepsbt`                | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `combinepsbt`               | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `finalizepsbt`              | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `createpsbt`                | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `converttopsbt`             | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `utxoupdatepsbt`            | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `joinpsbts`                 | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |
| `analyzepsbt`               | `-` [PR][bnew-psbt] | :heavy_check_mark: [PSBT PR][new-psbt]                  | :hourglass_flowing_sand: |

#### Blockchain
| RPC Method         | Bcoin              | Core               | Compatible |
| ----               | ----               | ----               | ----       |
| `gettxoutproof`    | :heavy_check_mark: | :heavy_check_mark: | :question: |
| `verifytxoutproof` | :heavy_check_mark: | :heavy_check_mark: | :question: |

[dep-signrawtx]: https://github.com/bitcoin/bitcoin/pull/10579
[new-combinerawtx]: https://github.com/bitcoin/bitcoin/pull/10571


## Wallet RPC Calls
### RPC Wallet
#### Raw Transactions
| RPC Method           | Bcoin              | Core               | Compatible |
| ----                 | ----               | ----               | ----       |
| `fundrawtransaction` | :heavy_check_mark: | :heavy_check_mark: | :question: |

#### Wallet
Since v0.17 account API has been replaced by labels API [CHANGELOG][lab-v-acc].

| RPC Method                     | Bcoin                 | Core                                                            | Compatible               |
| ----                           | ----                  | ----                                                            | ----                     |
| `resendwallettransactions`     | :heavy_check_mark:    | `-` [tests] [PR][dep-resendwtxs]                                | :x:                      |
| `abandontransaction`           | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `abortrescan`                  | `-`                   | :heavy_check_mark: [since v0.15] [PR][new-abortrescan]          | :x:                      |
| `addmultisigaddress`           | `-` `not implemented` | :heavy_check_mark:                                              | :x:                      |
| `backupwallet`                 | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `bumpfee`                      | `-`                   | :heavy_check_mark: [since v0.12] [rbf] [PR][new-bumpfee]        | :x:                      |
| `createwallet`                 | `-`                   | :heavy_check_mark: [since v0.17] [PR][new-createwallet]         | :x:                      |
| `dumpprivkey`                  | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `dumpwallet`                   | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `encryptwallet`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getaddressinfo`               | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getaccountaddress`            | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `getaccount`                   | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `getaddressesbylabel`          | `-`                   | :heavy_check_mark: [since v0.17] [account -> label][lab-v-acc]  | :x:                      |
| `getaddressesbyaccount`        | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `getbalance`                   | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `getnewaddress`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `getrawchangeaddress`          | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getreceivedbyaddress`         | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getreceivedbyaccount`         | `-`                   | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `getreceivedbylabel`           | `-`                   | :heavy_check_mark: [since v0.17] [account -> label][lab-v-acc]  | :x:                      |
| `gettransaction`               | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getunconfirmedbalance`        | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `getbalances`                  | `-`                   | :heavy_check_mark: [since next] [balances PR][new-balances]     | :x:                      |
| `getwalletinfo`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `importaddress`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `importmulti`                  | `-`                   | :heavy_check_mark: [since v0.14] [PR][new-importmulti]          | :x:                      |
| `importprivkey`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `importprunedfunds`            | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `importpubkey`                 | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `importwallet`                 | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `keypoolrefill`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `listaddressgroupings`         | `-` `not implemented` | :heavy_check_mark:                                              | :question:               |
| `listaccounts`                 | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `listlabels`                   | `-`                   | :heavy_check_mark: [since v0.17] [account -> label][lab-v-acc]  | :x:                      |
| `listlockunspent`              | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `listreceivedbyaddress`        | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `listreceivedbyaccount`        | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `listreceivedbylabel`          | `-`                   | :heavy_check_mark: [since v0.17] [account -> label][lab-v-acc]  | :x:                      |
| `listsinceblock`               | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `listtransactions`             | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `listunspent`                  | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `listwalletdir`                | `-`                   | :heavy_check_mark: [util] [since v0.18] [PR][new-listwalletdir] | :x:                      |
| `listwallets`                  | `-`                   | :heavy_check_mark: [since v0.15] [PR][new-listwallets]          | :x:                      |
| `loadwallet`                   | `-`                   | :heavy_check_mark: [since v0.17] [PR][new-loadwallet]           | :x:                      |
| `lockunspent`                  | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `removeprunedfunds`            | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `rescanblockchain`             | `-`                   | :heavy_check_mark: [since v0.16] [PR][new-rescanblockchain]     | :x:                      |
| `sendfrom`                     | :heavy_check_mark:    | `-` [deprecated v0.17] [account -> label][lab-v-acc]            | :x:                      |
| `sendmany`                     | :heavy_check_mark:    | :heavy_check_mark:                                              | :x:                      |
| `sendtoaddress`                | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `sethdseed`                    | `-`                   | :heavy_check_mark: [since v0.17] [PR][new-sethdseed]            | :x:                      |
| `setlabel`                     | `-`                   | :heavy_check_mark: [since v0.17] [account -> label][lab-v-acc]  | :x:                      |
| `settxfee`                     | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `signmessage`                  | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `signrawtransactionwithwallet` | `-`                   | :heavy_check_mark: [since v0.17] [PR][new-signrawtxwithwallet]  | :x:                      |
| `unloadwallet`                 | `-`                   | :heavy_check_mark: [since v0.17] [PR][new-unloadwallet]         | :x:                      |
| `walletcreatefundedpsbt`       | `-` [PR][bnew-psbt]   | :heavy_check_mark: [PSBT PR][new-psbt]                          | :hourglass_flowing_sand: |
| `walletlock`                   | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `walletpassphrase`             | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `walletpassphrasechange`       | :heavy_check_mark:    | :heavy_check_mark:                                              | :question:               |
| `walletprocesspsbt`            | `-` [PR][bnew-psbt]   | :heavy_check_mark: [PSBT PR][new-psbt]                          | :hourglass_flowing_sand: |
| `selectwallet`                 | :heavy_check_mark:    | `-` [never]                                                     | :x:                      |

[new-abortrescan]: https://github.com/bitcoin/bitcoin/pull/10208
[dep-resendwtxs]: https://github.com/bitcoin/bitcoin/pull/15680
[dep-addwitnessaddress]: https://github.com/bitcoin/bitcoin/pull/12210
[new-bumpfee]: https://github.com/bitcoin/bitcoin/pull/8456
[new-createwallet]: https://github.com/bitcoin/bitcoin/pull/13058
[lab-v-acc]: https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.17.0.md#label-and-account-apis-for-wallet
[new-balances]: https://github.com/bitcoin/bitcoin/pull/15930
[new-importmulti]: https://github.com/bitcoin/bitcoin/pull/7551
[new-listwallets]: https://github.com/bitcoin/bitcoin/pull/10604
[new-listwalletdir]: https://github.com/bitcoin/bitcoin/pull/14291
[new-loadwallet]: https://github.com/bitcoin/bitcoin/pull/10740
[new-unloadwallet]: https://github.com/bitcoin/bitcoin/pull/13111
[new-rescanblockchain]: https://github.com/bitcoin/bitcoin/pull/7061
[new-sethdseed]: https://github.com/bitcoin/bitcoin/pull/12560
[new-signrawtxwithwallet]: https://github.com/bitcoin/bitcoin/pull/10579

[new-psbt]:  https://github.com/bitcoin/bitcoin/pull/13557
[bnew-psbt]: https://github.com/bcoin-org/bcoin/pull/607

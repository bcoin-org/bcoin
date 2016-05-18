/**
 * An inverse enum. Retrieves key by value.
 * @typedef {Object} RevMap
 * @global
 */

/**
 * @typedef {Object} InvItem
 * @property {Number|String} type - Inv type. See {@link constants.inv}.
 * @property {Hash|Buffer} hash
 * @global
 */

/**
 * @typedef {Object} Outpoint
 * @property {Hash} hash
 * @property {Number} index
 * @global
 */

/**
 * Can be `pubkeyhash`, `scripthash`, `witnesspubkeyhash`,
 * or `witnessscripthash`, or an address prefix
 * (see {@link network.address}).
 * @typedef {String|Number} AddressType
 * @global
 */

/**
 * @typedef {Object} ParsedAddress
 * @property {Number?} version - Witness program version (-1 if not present).
 * @property {AddressType} type
 * @property {Buffer} hash
 * @global
 */

/**
 * A bitfield containing locktime flags.
 * @typedef {Number} LockFlags
 * @global
 */

/**
 * @typedef {Object} Seed
 * @property {String} host
 * @property {Number} port
 * @global
 */

/**
 * @typedef {Object} ParsedURI
 * @property {Base58Address} address
 * @property {Amount?} amount? - Amount in satoshis.
 * @property {String?} label
 * @property {String?} message
 * @property {String?} request - Payment request URL.
 * @global
 */

/**
 * Wallet ID
 * @typedef {String} WalletID
 * @global
 */

/**
 * Base58 string.
 * @typedef {String} Base58String
 * @global
 */

/**
 * Base58 address.
 * @typedef {String} Base58Address
 * @global
 */

/**
 * Hex-string hash.
 * @typedef {String} Hash
 * @global
 */

/**
 * Reversed hex-string hash (uint256le).
 * @typedef {String} ReversedHash
 * @global
 */

/**
 * Signature hash type. One of `all`, `single`, `none`, or
 * one of {@link constants.hashType}.
 * @typedef {String|Number} SighashType
 * @global
 */

/**
 * Wallet balance.
 * @typedef {Object} Balance
 * @property {Amount} confirmed
 * @property {Amount} unconfirmed
 * @property {Amount} total
 * @global
 */

/**
 * A satoshi amount. This is technically a
 * JS double float, but it is regularly
 * enforced to be less than 53 bits and
 * less than MAX_MONEY regularly in
 * various functions.
 * @typedef {Number} Amount
 * @global
 */

/**
 * Rate of satoshis per kB.
 * @typedef {Amount} Rate
 * @global
 */

/**
 * A big number (bn.js)
 * @typedef {Object} BN
 * @global
 */

/**
 * A bitfield containing script verify flags.
 * @typedef {Number} VerifyFlags
 * @global
 */

/**
 * @typedef {Object} Program
 * @property {Number} version - Ranges from 0 to 16.
 * @property {String|null} type - Null if malformed. `unknown` if unknown
 * version (treated as anyone-can-spend). Otherwise one of `witnesspubkeyhash`
 * or `witnessscripthash`.
 * @property {Buffer} data - Usually the hash.
 * @global
 */

/**
 * @typedef {Object} Orphan
 * @property {Hash} hash - Orphan TX hash.
 * @property {Number} index - Orphan input index.
 * @global
 */

/**
 * @typedef {Object} CoinSelection
 * @property {Coin[]?} chosen - Selected coins.
 * @property {Amount} change - Amount of change to add.
 * @property {Amount} fee - Estimated fee.
 * @property {Amount} total - Total value.
 * @global
 */

/**
 * @typedef {Object} DeploymentState
 * @property {VerifyFlags} flags
 * @property {LockFlags} lockFlags
 * @property {Boolean} coinbaseHeight - Whether coinbase height is enforced.
 * @property {Boolean} segwit
 * @property {Boolean} csv
 * @global
 */

/**
 * @typedef {Object} SubmitOrderPacket
 * @property {Hash} hash
 * @property {NakedTX} tx
 * @global
 */

/**
 * @typedef {Object} ReplyPacket
 * @property {Hash} hash
 * @property {Number} code
 * @property {Buffer} publicKey
 * @global
 */

/**
 * @typedef {Object} FilterLoadPacket
 * @see Bloom
 * @property {Buffer} filter - Serialized bloom filter.
 * @property {Number} n - Number of hash functions.
 * @property {Number} tweak - Bloom filter seed.
 * @property {String|Number} update (See {@link constants.filterFlags}).
 * @global
 */

/**
 * @typedef {Object} FilterAddPacket
 * @see Bloom
 * @property {Buffer} data - Data to add to filter.
 * @global
 */

/**
 * @typedef {Object} GetUTXOsPacket
 * @property {Boolean} mempool - Check mempool.
 * @property {Outpoint[]} prevout - Outpoints.
 * @global
 */

/**
 * @typedef {Object} NakedCoin
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Amount} value - Output value in satoshis.
 * @property {Script} script - Output script.
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} index - Output index.
 * @global
 */

/**
 * @typedef {Object} UTXOsPacket
 * @property {Array?} data.hits - Hits (array of
 * 1s and 0s representing a bit mask).
 * @property {Buffer?} data.map - Hit map.
 * @property {Object} data.height - Chain height.
 * @property {Hash} data.tip - Chain tip hash.
 * @property {NakedCoin[]} data.coins
 * @global
 */

/**
 * @typedef {Object} PingPacket
 * @property {BN} nonce
 * @global
 */

/**
 * @typedef {Object} NetworkAddress
 * @property {Number?} ts - Timestamp.
 * @property {Number?} services - Service bits.
 * @property {Buffer?} ipv4 - IPv4 address.
 * @property {Buffer?} ipv6 - IPv6 address.
 * @property {Number?} port - Port.
 * @property {Boolean?} network - Whether network services are enabled.
 * @property {Boolean?} getutxo - Whether peer supports getutxos.
 * @property {Boolean?} bloom - Whether peer supports serving FILTERED_BLOCKs.
 * @property {Boolean?} witness - Whether peer supports segwit.
 * @global
 */

/**
 * @typedef {Object} VersionPacket
 * @property {Number} version - Protocol version.
 * @property {Number} services - Service bits.
 * @property {Number} ts - Timestamp of discovery.
 * @property {NetworkAddress} local - Our address.
 * @property {NetworkAddress} remote - Their address.
 * @property {BN} nonce
 * @property {String} agent - User agent string.
 * @property {Number} height - Chain height.
 * @property {Boolean} relay - Whether transactions
 * should be relayed immediately.
 * @global
 */

/**
 * @typedef {Object} GetBlocksPacket
 * @property {Number} version - Protocol version.
 * @property {Hash[]} locator - Chain locator.
 * @property {Hash} stop - Hash to stop at.
 * @global
 */

/**
 * @typedef {Object} NakedBlock
 * @property {Number} version - Transaction version. Note that BCoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Hash} prevBlock
 * @property {Hash} merkleRoot
 * @property {Number} ts
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} height
 * @property {Number} totalTX
 * @property {NakedTX[]?} txs - Only present on blocks.
 * @property {Hash[]?} hashes - Only present on merkleblocks.
 * @property {Buffer?} flags - Only present on merkleblocks.
 * @property {Number?} coinbaseHeight - Only present on compactblocks.
 * @global
 */

/**
 * @typedef {Object} NakedInput
 * @property {Outpoint} prevout
 * @property {NakedScript} script - Input script.
 * @property {Number} sequence - nSequence.
 * @property {NakedWitness} witness - Witness.
 * @global
 */

/**
 * @typedef {Object} NakedOutput
 * @property {Amount} value - Value in satoshis.
 * @property {NakedScript} script - Output script.
 * @global
 */

/**
 * @typedef {Object} NakedCoin
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {Amount} value - Output value in satoshis.
 * @property {Script} script - Output script.
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} index - Output index.
 * @global
 */

/**
 * @typedef {Object} NakedTX
 * @property {Number} version
 * @property {Number} flag
 * @property {NakedInput[]} inputs
 * @property {NakedOutput[]} outputs
 * @property {Number} locktime
 * @global
 */

/**
 * @typedef {Object} NakedScript
 * @property {Buffer} raw - Raw code.
 * @property {Array} code - Parsed code.
 * @global
 */

/**
 * @typedef {Object} NakedWitness
 * @param {Buffer[]} items - Stack items.
 * @global
 */

/**
 * @typedef {Object} RejectPacket
 * @param {(Number|String)?} ccode - Code
 * (see {@link constants.reject}).
 * @param {String?} msg - Message.
 * @param {String?} reason - Reason.
 * @param {(Hash|Buffer)?} data - Transaction or block hash.
 * @global
 */

/**
 * @typedef {Object} AlertPacket
 * @property {Number} version
 * @property {Number} relayUntil
 * @property {Number} expiration
 * @property {Number} id
 * @property {Number} cancel
 * @property {Number[]} cancels
 * @property {Number} minVer
 * @property {Number} maxVer
 * @property {String[]} subVers
 * @property {Number} priority
 * @property {String} comment
 * @property {String} statusBar
 * @property {String?} reserved
 * @property {Buffer?} payload - Payload.
 * @property {Buffer?} signature - Payload signature.
 * @property {Buffer?} key - Private key to sign with.
 * @global
 */

/**
 * One of `main`, `testnet`, `regtest`, `segnet3`, `segnet4`.
 * @typedef {String} NetworkType
 * @see {module:network.types}
 * @global
 */

/*
 * Callbacks & Events
 */

/**
 * @callback TXCallback
 * @param {Error?} err
 * @param {TX} tx
 * @global
 */

/**
 * @callback TXSCallback
 * @param {Error?} err
 * @param {TX[]} txs
 * @global
 */

/**
 * @callback MTXCallback
 * @param {Error?} err
 * @param {MTX} tx
 * @global
 */

/**
 * @callback MTXSCallback
 * @param {Error?} err
 * @param {MTX[]} txs
 * @global
 */

/**
 * @callback CoinCallback
 * @param {Error?} err
 * @param {Coin} tx
 * @global
 */

/**
 * @callback CoinsCallback
 * @param {Error?} err
 * @param {Coin[]} tx
 * @global
 */

/**
 * @callback VerifyCallback
 * @param {VerifyError?} err
 * @global
 */

/**
 * @callback BlockCallback
 * @param {Error?} err
 * @param {Block} block
 * @global
 */

/**
 * @callback EntryCallback
 * @param {Error?} err
 * @param {ChainEntry} entry
 * @global
 */

/**
 * @callback EntriesCallback
 * @param {Error?} err
 * @param {ChainEntry[]} entry
 * @global
 */

/**
 * @callback BalanceCallback
 * @param {Error?} err
 * @param {Balance} balance
 * @global
 */

/**
 * @callback BooleanCallback
 * @param {Error?} err
 * @param {Boolean} result
 * @global
 */

/**
 * @callback NumberCallback
 * @param {Error?} err
 * @param {Number} result
 * @global
 */

/**
 * @callback HashCallback
 * @param {Error?} err
 * @param {Hash} hash
 * @global
 */

/**
 * @callback HashesCallback
 * @param {Error?} err
 * @param {Hash[]} hash
 * @global
 */

/**
 * @callback WalletCallback
 * @param {Error?} err
 * @param {Wallet|NakedWallet} wallet
 * @global
 */

/**
 * @callback BufferCallback
 * @param {Error?} err
 * @param {Buffer} data
 * @global
 */

/**
 * @callback ObjectCallback
 * @param {Error?} err
 * @param {Object} obj
 * @global
 */

/**
 * @callback DeploymentCallback
 * @param {(Error|VerifyError)?} err
 * @param {DeploymentState} state
 * @global
 */

/**
 * @callback MinerBlockCallback
 * @param {Error?} err
 * @param {MinerBlock} block
 * @global
 */

/**
 * @callback AddressMapCallback
 * @param {Error?} err
 * @param {AddressMap} map
 * @global
 */

/**
 * @callback AddressTableCallback
 * @param {Error?} err
 * @param {AddressTable} table
 * @global
 */

/**
 * @callback OrphanCallback
 * @param {Error?} err
 * @param {Orphan} orphan
 * @global
 */

/**
 * @callback TSHeightCallback
 * @param {Error?} err
 * @param {Number} ts
 * @param {Number} height
 * @global
 */

/**
 * @callback ConfidenceCallback
 * @param {Error?} err
 * @param {Confidence} confidence
 * @global
 */

/**
 * @callback HashHeightCallback
 * @param {Error?} err
 * @param {Hash} hash
 * @param {Number} height
 * @global
 */

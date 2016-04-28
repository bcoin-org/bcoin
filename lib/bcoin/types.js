/**
 * An inverse enum. Retrieves key by value.
 * @global
 * @typedef {Object} RevMap
 */

/**
 * @typedef {Object} InvItem
 * @global
 * @property {Number|String} type - Inv type. See {@link constants.inv}.
 * @property {Hash|Buffer} hash
 */

/**
 * @typedef {Object} Outpoint
 * @global
 * @property {Hash} hash
 * @property {Number} index
 */

/**
 * Can be `pubkeyhash`, `scripthash`, `witnesspubkeyhash`,
 * or `witnessscripthash`, or an address prefix
 * (see {@link network.address}).
 * @global
 * @typedef {String|Number} AddressType
 */

/**
 * @typedef {Object} ParsedAddress
 * @global
 * @property {Number?} version - Witness program version (-1 if not present).
 * @property {AddressType} type
 * @property {Buffer} hash
 */

/**
 * A bitfield containing locktime flags.
 * @global
 * @typedef {Number} LockFlags
 */

/**
 * @typedef {Object} Seed
 * @global
 * @property {String} host
 * @property {Number} port
 */

/**
 * @typedef {EventEmitter} BroadcastPromise
 * @global
 * @emits BroadcastPromise#ack
 * @emits BroadcastPromise#timeout
 * @emits BroadcastPromise#reject
 */

/**
 * @typedef {Object} ParsedURI
 * @global
 * @property {Base58Address} address
 * @property {BN?} amount? - Amount in satoshis.
 * @property {String?} label
 * @property {String?} message
 * @property {String?} request - Payment request URL.
 */

/**
 * Wallet ID
 * @global
 * @typedef {String} WalletID
 */

/**
 * Base58 string.
 * @global
 * @typedef {String} Base58String
 */

/**
 * Base58 address.
 * @global
 * @typedef {String} Base58Address
 */

/**
 * Hex-string hash.
 * @global
 * @typedef {String} Hash
 */

/**
 * Reversed hex-string hash (uint256le).
 * @global
 * @typedef {String} ReversedHash
 */

/**
 * Signature hash type. One of `all`, `single`, `none`, or
 * one of {@link constants.hashType}.
 * @global
 * @typedef {String|Number} SighashType
 */

/**
 * Wallet balance.
 * @global
 * @typedef {Object} Balance
 * @property {BN} confirmed
 * @property {BN} unconfirmed
 * @property {BN} total
 */

/**
 * A big number (bn.js)
 * @global
 * @typedef {Object} BN
 */

/**
 * A bitfield containing script verify flags.
 * @global
 * @typedef {Number} VerifyFlags
 */

/**
 * @typedef {Object} Program
 * @property {Number} version - Ranges from 0 to 16.
 * @property {String|null} type - Null if malformed. `unknown` if unknown
 * version (treated as anyone-can-spend). Otherwise one of `witnesspubkeyhash`
 * or `witnessscripthash`.
 * @property {Buffer} data - Usually the hash.
 */

/**
 * @typedef {Object} Orphan
 * @property {Hash} hash - Orphan TX hash.
 * @property {Number} index - Orphan input index.
 */

/**
 * @typedef {Object} SubmitOrderPacket
 * @global
 * @property {Hash} hash
 * @property {NakedTX} tx
 * @property {Number} _size
 */

/**
 * @typedef {Object} ReplyPacket
 * @global
 * @property {Hash} hash
 * @property {Number} code
 * @property {Buffer} publicKey
 * @property {Number} _size
 */

/**
 * @typedef {Object} FilterLoadPacket
 * @global
 * @see Bloom
 * @property {Buffer} filter - Serialized bloom filter.
 * @property {Number} n - Number of hash functions.
 * @property {Number} tweak - Bloom filter seed.
 * @property {String|Number} update (See {@link constants.filterFlags}).
 * @property {Number} _size
 */


/**
 * @typedef {Object} FilterAddPacket
 * @global
 * @see Bloom
 * @property {Buffer} data - Data to add to filter.
 * @property {Number} _size
 */


/**
 * @typedef {Object} GetUTXOsPacket
 * @global
 * @property {Boolean} mempool - Check mempool.
 * @property {Outpoint[]} prevout - Outpoints.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedCoin
 * @global
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {BN} value - Output value in satoshis.
 * @property {Script} script - Output script.
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} index - Output index.
 */

/**
 * @typedef {Object} UTXOsPacket
 * @global
 * @property {Array?} data.hits - Hits (array of
 * 1s and 0s representing a bit mask).
 * @property {Buffer?} data.map - Hit map.
 * @property {Object} data.height - Chain height.
 * @property {Hash} data.tip - Chain tip hash.
 * @property {NakedCoin[]} data.coins
 * @property {Number} _size
 */

/**
 * @typedef {Object} PingPacket
 * @global
 * @property {BN} nonce
 * @property {Number} _size
 */

/**
 * @typedef {Object} NetworkAddress
 * @global
 * @property {Number?} ts - Timestamp.
 * @property {Number?} services - Service bits.
 * @property {Buffer?} ipv4 - IPv4 address.
 * @property {Buffer?} ipv6 - IPv6 address.
 * @property {Number?} port - Port.
 * @property {Boolean?} network - Whether network services are enabled.
 * @property {Boolean?} getutxo - Whether peer supports getutxos.
 * @property {Boolean?} bloom - Whether peer supports serving FILTERED_BLOCKs.
 * @property {Boolean?} witness - Whether peer supports segwit.
 * @property {Number} _size
 */

/**
 * @typedef {Object} VersionPacket
 * @global
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
 * @property {Number} _size
 */

/**
 * @typedef {Object} GetBlocksPacket
 * @global
 * @property {Number} version - Protocol version.
 * @property {Hash[]} locator - Chain locator.
 * @property {Hash} stop - Hash to stop at.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedBlock
 * @global
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
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedInput
 * @global
 * @property {Outpoint} prevout
 * @property {NakedScript} script - Input script.
 * @property {Number} sequence - nSequence.
 * @property {NakedWitness} witness - Witness.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedOutput
 * @global
 * @property {BN} value - Value in satoshis.
 * @property {NakedScript} script - Output script.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedCoin
 * @global
 * @property {Number} version - Transaction version.
 * @property {Number} height - Transaction height (-1 if unconfirmed).
 * @property {BN} value - Output value in satoshis.
 * @property {Script} script - Output script.
 * @property {Boolean} coinbase - Whether the containing
 * transaction is a coinbase.
 * @property {Hash} hash - Transaction hash.
 * @property {Number} index - Output index.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedTX
 * @global
 * @property {Number} version
 * @property {Number} flag
 * @property {NakedInput[]} inputs
 * @property {NakedOutput[]} outputs
 * @property {Number} locktime
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedScript
 * @global
 * @property {Buffer} raw - Raw code.
 * @property {Array} code - Parsed code.
 * @property {Number} _size
 */

/**
 * @typedef {Object} NakedWitness
 * @global
 * @param {Buffer[]} items - Stack items.
 * @property {Number} _size
 */

/**
 * @typedef {Object} RejectPacket
 * @global
 * @param {(Number|String)?} ccode - Code
 * (see {@link constants.reject}).
 * @param {String?} msg - Message.
 * @param {String?} reason - Reason.
 * @param {(Hash|Buffer)?} data - Transaction or block hash.
 * @property {Number} _size
 */

/**
 * @typedef {Object} AlertPacket
 * @global
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
 * @property {Number} _size
 */

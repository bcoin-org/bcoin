/**
 * An inverse enum. Retrieves key by value.
 * @typedef {Object} RevMap
 * @global
 */

/**
 * One of {@link module:constants.inv}.
 * @typedef {Number|String} InvType
 * @global
 */

/**
 * An output script type.
 * @see {module:constants.scriptTypes}
 * May sometimes be a string if specified.
 * @typedef {Number|String} ScriptType
 * @global
 */

/**
 * A subset of {@link ScriptType}, including
 * pubkeyhash, scripthash, witnesspubkeyhash,
 * and witnessscripthash. This value
 * specifically refers to the address prefix.
 * It is a network-agnostic way of representing
 * prefixes. May sometimes be a string if
 * specified.
 * @typedef {Number|String} AddressType
 * @global
 */

/**
 * A bitfield containing locktime flags.
 * @typedef {Number} LockFlags
 * @global
 */

/**
 * Unix time (seconds).
 * @typedef {Number} Seconds
 * @global
 */

/**
 * Unix time (milliseconds).
 * @typedef {Number} Milliseconds
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
 * Buffer or hex-string hash.
 * @typedef {Buffer|String} Hash
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
 * A satoshi amount. This is technically a
 * JS double float, but it is regularly
 * enforced to be less than 53 bits and
 * less than MAX_MONEY in various
 * functions.
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
 * @property {Buffer[]} items - Stack items.
 * @global
 */

/**
 * One of `main`, `testnet`, `regtest`, `segnet3`, `segnet4`.
 * @typedef {String} NetworkType
 * @see {module:network.types}
 * @global
 */

'use strict';

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
 * Base58 string.
 * @typedef {String} Base58String
 * @global
 */

/**
 * Bech32 string.
 * @typedef {String} Bech32String
 * @global
 */

/**
 * Serialized address.
 * @typedef {Base58String|Bech32String} AddressString
 * @global
 */

/**
 * Buffer or hex-string hash.
 * @typedef {Buffer|String} Hash
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
 * One of `main`, `testnet`, `regtest`, `segnet3`, `segnet4`.
 * @typedef {String} NetworkType
 * @see {module:network.types}
 * @global
 */

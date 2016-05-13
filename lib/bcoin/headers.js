/*!
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = require('./utils');

/**
 * Represents block headers obtained from the network via `headers`.
 * @exports Headers
 * @constructor
 * @extends AbstractBlock
 * @param {NakedBlock} data
 * @property {Number} version - Block version. Note
 * that BCoin reads versions as unsigned despite
 * them being signed on the protocol level. This
 * number will never be negative.
 * @property {Hash} prevBlock - Previous block hash.
 * @property {Hash} merkleRoot - Merkle root hash.
 * @property {Number} ts - Timestamp.
 * @property {Number} bits
 * @property {Number} nonce
 * @property {Number} totalTX - Transaction count.
 * @property {Number} height - Block height (-1 if not present).
 * @property {ReversedHash} rhash - Reversed block hash (uint256le).
 */

function Headers(data) {
  if (!(this instanceof Headers))
    return new Headers(data);

  bcoin.abstractblock.call(this, data);
}

utils.inherits(Headers, bcoin.abstractblock);

/**
 * Serialize the header into a `headers` packet.
 * @returns {Buffer}
 */

Headers.prototype.render = function render() {
  return this.getRaw();
};

/**
 * Do non-contextual verification on the headers.
 * @alias verify
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

Headers.prototype._verify = function _verify(ret) {
  return this.verifyHeaders(ret);
};

/**
 * Get size of the headers.
 * @returns {Number}
 */

Headers.prototype.getSize = function getSize() {
  if (this._size == null)
    this.getRaw();
  return this._size;
};

/**
 * Get the raw headers serialization.
 * @returns {Buffer}
 */

Headers.prototype.getRaw = function getRaw() {
  if (!this._raw) {
    this._raw = bcoin.protocol.framer.headers([this]);
    this._size = this._raw.length;
  }
  return this._raw;
};

/**
 * Inspect the headers and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

Headers.prototype.inspect = function inspect() {
  var copy = bcoin.headers(this);
  copy.__proto__ = null;
  delete copy._raw;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.date = utils.date(copy.ts);
  return copy;
};

/**
 * Serialize the headers.
 * @see {Headers#render}
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

Headers.prototype.toRaw = function toRaw(enc) {
  var data;

  data = this.render();

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized headers.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedBlock} A "naked" headers object.
 */

Headers.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseHeaders(data)[0];
};

/**
 * Instantiate headers from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Headers}
 */

Headers.fromRaw = function fromRaw(data, enc) {
  return new Headers(Headers.parseRaw(data, enc));
};

/**
 * Test an object to see if it is a Headers object.
 * @param {Object} obj
 * @returns {Boolean}
 */

Headers.isHeaders = function isHeaders(obj) {
  return obj
    && !obj.txs
    && typeof obj.abbr === 'function'
    && typeof obj.toBlock !== 'function';
};

module.exports = Headers;

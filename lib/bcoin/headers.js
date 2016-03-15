/**
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Headers
 */

function Headers(data) {
  var self = this;

  if (!(this instanceof Headers))
    return new Headers(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'headers';

  if (!this._raw)
    this._raw = this.render();

  if (!this._size)
    this._size = this._raw.length;
}

utils.inherits(Headers, bcoin.abstractblock);

Headers.prototype.render = function render() {
  if (this._raw)
    return this._raw;
  return bcoin.protocol.framer.headers(this);
};

Headers.prototype._verify = function _verify() {
  return this.verifyHeaders();
};

Headers.prototype.inspect = function inspect() {
  var copy = bcoin.headers(this);
  copy.__proto__ = null;
  delete copy._raw;
  delete copy._chain;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

Headers.prototype.toRaw = function toRaw(enc) {
  var data;

  data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

Headers._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseHeaders(data);
};

Headers.fromRaw = function fromRaw(data, enc) {
  return new Headers(Headers._fromRaw(data, enc));
};


/**
 * Expose
 */

module.exports = Headers;

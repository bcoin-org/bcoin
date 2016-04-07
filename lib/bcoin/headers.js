/**
 * headers.js - headers object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var utils = require('./utils');

/**
 * Headers
 */

function Headers(data) {
  if (!(this instanceof Headers))
    return new Headers(data);

  bcoin.abstractblock.call(this, data);

  this.type = 'headers';
}

utils.inherits(Headers, bcoin.abstractblock);

Headers.prototype.render = function render() {
  return this.getRaw();
};

Headers.prototype._verify = function _verify() {
  return this.verifyHeaders();
};

Headers.prototype.getSize = function getSize() {
  if (this._size == null)
    this.getRaw();
  return this._size;
};

Headers.prototype.getRaw = function getRaw() {
  if (!this._raw) {
    this._raw = bcoin.protocol.framer.headers(this);
    this._size = this._raw.length;
  }
  return this._raw;
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

Headers.isHeaders = function isHeaders(obj) {
  return obj && obj.type === 'headers' && typeof obj.render === 'function';
};

/**
 * Expose
 */

return Headers;
};

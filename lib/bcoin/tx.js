var bcoin = require('../bcoin');
var utils = bcoin.utils;

function TX(data) {
  if (!(this instanceof TX))
    return new TX(data);
  this.type = 'tx';

  this._hash = null;
  this._raw = data || null;
}
module.exports = TX;

TX.prototype.hash = function hash(enc) {
  if (!this._hash) {
    // First, obtain the raw TX data
    this.render();

    // Hash it
    this._hash = utils.dsha256(this._raw);
  }
  return enc === 'hex' ? utils.toHex(this._hash) : this._hash;
};

TX.prototype.render = function render(framer) {
  return [];
};

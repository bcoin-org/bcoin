var bcoin = require('../bcoin');
var utils = bcoin.utils;

function TX(data) {
  if (!(this instanceof TX))
    return new TX(data);
  this.type = 'tx';

  this.version = data.version;
  this.inputs = data.inputs.map(function(input) {
    return {
      out: {
        hash: utils.toHex(input.out.hash),
        index: bcoin.script.parse(input.out.index)
      },
      script: input.script,
      seq: input.seq
    };
  });
  this.outputs = data.outputs.map(function(output) {
    return {
      value: output.value,
      script: bcoin.script.parse(output.script)
    };
  });
  this.lock = data.lock;

  this._hash = null;
  this._raw = data._raw || null;
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

TX.prototype.verify = function verify() {
};

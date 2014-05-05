var assert = require('assert');
var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;

function TX(data) {
  if (!(this instanceof TX))
    return new TX(data);
  this.type = 'tx';

  if (!data)
    data = {};

  this.version = data.version || 1;
  this.inputs = [];
  this.outputs = [];
  this.lock = data.lock || 0;

  this._hash = null;
  this._raw = data._raw || null;

  if (data.inputs) {
    data.inputs.forEach(function(input) {
      this.input(input);
    }, this);
  }
  if (data.outputs) {
    data.outputs.forEach(function(out) {
      this.out(out);
    }, this);
  }
}
module.exports = TX;

TX.prototype.clone = function clone() {
  return new TX(this);
};

TX.prototype.hash = function hash(enc) {
  if (!this._hash) {
    // First, obtain the raw TX data
    this.render();

    // Hash it
    this._hash = utils.dsha256(this._raw);
  }
  return enc === 'hex' ? utils.toHex(this._hash) : this._hash;
};

TX.prototype.render = function render() {
  return bcoin.protocol.framer.tx(this);
};

TX.prototype.input = function input(i, index) {
  if (i instanceof TX)
    i = { tx: i, index: index };

  var hash;
  if (i.tx)
    hash = i.tx.hash('hex');
  else if (i.out)
    hash = i.out.hash;
  else
    hash = i.hash;

  this.inputs.push({
    out: {
      tx: i.tx,
      hash: hash,
      index: i.out ? i.out.index : i.index,
    },
    script: bcoin.script.decode(i.script),
    seq: i.seq === undefined ? 0xffffffff : i.seq
  });

  return this;
};

TX.prototype.out = function out(output, value) {
  if (typeof output === 'string') {
    output = {
      address: output,
      value: value
    };
  }

  var script = bcoin.script.decode(output.script);

  // Default script if given address
  if (output.address) {
    script = [
      'dup',
      'hash160',
      bcoin.wallet.addr2hash(output.address),
      'eqverify',
      'checksig'
    ];
  }

  this.outputs.push({
    value: new bn(output.value),
    script: script
  });

  return this;
};

TX.prototype.getSubscript = function getSubscript(index) {
  var output = this.outputs[index];
  assert(output);

  var script = output.script;
  return bcoin.script.subscript(script);
};

TX.prototype.subscriptHash = function subscriptHash(index, s, type) {
  var copy = this.clone();

  copy.inputs.forEach(function(input, i) {
    input.script = index === i ? s : [];
  });
  var verifyStr = copy.render();
  verifyStr = verifyStr.concat(
    bcoin.protocol.constants.hashType[type], 0, 0, 0
  );
  var hash = utils.dsha256(verifyStr);

  return hash;
};

TX.prototype.validate = function validate() {
  return this.inputs.every(function(input, i) {
    assert(input.out.tx);
    assert(input.out.tx.outputs.length > input.out.index);

    var subscript = input.out.tx.getSubscript(input.out.index);
    var hash = this.subscriptHash(i, subscript, 'all');

    var stack = [];
    bcoin.script.execute(input.script, stack);
    var prev = input.out.tx.outputs[input.out.index].script;
    var res = bcoin.script.execute(prev, stack, hash);
    if (!res)
      return false;

    return stack.length > 0 && utils.isEqual(stack.pop(), [ 1 ]);
  }, this);
};

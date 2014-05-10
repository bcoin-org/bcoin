var assert = require('assert');
var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;

function TX(data, block) {
  if (!(this instanceof TX))
    return new TX(data, block);
  this.type = 'tx';

  if (!data)
    data = {};

  this.version = data.version || 1;
  this.inputs = [];
  this.outputs = [];
  this.lock = data.lock || 0;
  this.ts = data.ts || 0;
  this.funds = new bn(0);

  this._hash = null;
  this._raw = data._raw || null;

  if (data.inputs) {
    data.inputs.forEach(function(input) {
      this.input(input, null);
    }, this);
  }
  if (data.outputs) {
    data.outputs.forEach(function(out) {
      this.out(out, null);
    }, this);
  }

  if (!data.ts && block && block.hasMerkle(this.hash('hex')))
    this.ts = block.ts;
}
module.exports = TX;

TX.prototype.clone = function clone() {
  return new TX(this);
};

TX.prototype.hash = function hash(enc) {
  var h = utils.dsha256(this.render());
  return enc === 'hex' ? utils.toHex(h) : h;
};

TX.prototype.render = function render() {
  return bcoin.protocol.framer.tx(this);
};

TX.prototype.input = function input(i, index) {
  if (i instanceof TX)
    i = { tx: i, index: index };
  else if (typeof i === 'string' || Array.isArray(i))
    i = { hash: i, index: index };

  var hash;
  if (i.tx)
    hash = i.tx.hash('hex');
  else if (i.out)
    hash = i.out.hash;
  else
    hash = i.hash;

  if (typeof hash !== 'string')
    hash = utils.toHex(hash);

  var input = {
    out: {
      tx: (i.out ? i.out.tx : i.tx) || null,
      hash: hash,
      index: i.out ? i.out.index : i.index,
    },
    script: i.script ? i.script.slice() : [],
    seq: i.seq === undefined ? 0xffffffff : i.seq
  };

  // Try modifying existing input first
  for (var i = 0; i < this.inputs.length; i++) {
    var ex = this.inputs[i];
    if (ex.out.hash !== hash && ex.out.index !== index)
      continue;

    ex.out.tx = input.out.tx || ex.out.tx;
    ex.seq = input.seq || ex.seq;
    ex.script = input.script.length ? input.script : ex.script;
    break;
  }
  if (i === this.inputs.length) {
    this.inputs.push(input);
    if (input.out.tx)
      this.funds.iadd(input.out.tx.outputs[input.out.index].value);
  }

  return this;
};

TX.prototype.out = function out(output, value) {
  if (output instanceof bcoin.wallet)
    output = output.getAddress();
  if (typeof output === 'string') {
    output = {
      address: output,
      value: value
    };
  }

  var script = output.script ? output.script.slice() : [];

  // Multisig script if given addresses
  if (Array.isArray(output.keys || output.address)) {
    var keys = output.keys || output.address;
    script = [
      [ output.minSignatures || keys.length ]
    ].concat(
      keys,
      [ [ keys.length ], 'checkmultisig' ]
    );
  // Default script if given address
  } else if (output.address) {
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

TX.prototype.verify = function verify() {
  return this.inputs.every(function(input, i) {
    if (!input.out.tx)
      return false;

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

TX.prototype.maxSize = function maxSize() {
  // Create copy with 0-script inputs
  var copy = this.clone();
  copy.inputs.forEach(function(input) {
    input.script = [];
  });

  var size = copy.render().length;

  // Add size for signatures and public keys
  copy.inputs.forEach(function(input) {
    var s = input.out.tx.outputs[input.out.index].script;
    if (bcoin.script.isPubkeyhash(s)) {
      // Signature + len
      size += 74;
      // Pub key + len
      size += 34;
      return;
    }

    // Multisig
    // Empty byte
    size += 1;
    // Signature + len
    size += 74;
  });

  return size;
};

TX.prototype.toJSON = function toJSON() {
  // Compact representation
  var ts = new Array(4);
  bcoin.utils.writeU32(ts, this.ts, 0);
  return utils.toHex(this.render().concat(ts));
};

TX.fromJSON = function fromJSON(json) {
  // Compact representation
  var data = utils.toArray(json, 'hex');
  var tx = data.slice(0, -4);
  var ts = bcoin.utils.readU32(data, data.length - 4);

  tx = new TX(new bcoin.protocol.parser().parseTX(tx));
  tx.ts = ts;

  return tx;
};

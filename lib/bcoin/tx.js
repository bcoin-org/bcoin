var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;

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
  this.block = null;

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

  if (!data.ts && block && block.hasTX(this.hash('hex'))) {
    this.ts = block.ts;
    this.block = block.hash('hex');
  }

  // ps = Pending Since
  this.ps = this.ts === 0 ? +new Date() / 1000 : 0;
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

TX.prototype._input = function _input(i, index) {
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
      hash: utils.toHex(hash),
      index: i.out ? i.out.index : i.index,
    },
    script: i.script ? i.script.slice() : [],
    seq: i.seq === undefined ? 0xffffffff : i.seq
  };

  // Try modifying existing input first
  var index = this._inputIndex(hash, index);
  if (index !== -1) {
    var ex = this.inputs[index];

    ex.out.tx = input.out.tx || ex.out.tx;
    ex.seq = input.seq || ex.seq;
    ex.script = input.script.length ? input.script : ex.script;
  } else {
    this.inputs.push(input);
    index = this.inputs.length - 1;
  }

  return index;
};

TX.prototype._inputIndex = function _inputIndex(hash, index) {
  if (hash instanceof TX)
    hash = hash.hash('hex');
  for (var i = 0; i < this.inputs.length; i++) {
    var ex = this.inputs[i];
    if (ex.out.hash === hash && ex.out.index === index)
      return i;
  }

  return -1;
};

TX.prototype.input = function input(i, index) {
  this._input(i, index);
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

TX.prototype.verify = function verify(index, force) {
  // Valid if included in block
  if (!force && this.ts !== 0)
    return true;

  return this.inputs.every(function(input, i) {
    if (index !== undefined && index !== i)
      return true;

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

TX.prototype.inputAddrs = function inputAddrs() {
  return this.inputs.filter(function(input) {
    return bcoin.script.isPubkeyhashInput(input.script);
  }).map(function(input) {
    var pub = input.script[1];
    var hash = utils.ripesha(pub);
    return bcoin.wallet.hash2addr(hash);
  });
};

TX.prototype.funds = function funds(side) {
  if (side === 'in') {
    var inputs = this.inputs.filter(function(input) {
      return input.out.tx;
    });

    var acc = new bn(0);
    if (inputs.length === 0)
      return acc;

    inputs.reduce(function(acc, input) {
      return acc.iadd(input.out.tx.outputs[input.out.index].value);
    }, acc);

    return acc;
  }

  // Output
  var acc = new bn(0);
  if (this.outputs.length === 0)
    return acc;

  this.outputs.reduce(function(acc, output) {
    return acc.iadd(output.value);
  }, acc);

  return acc;
};

TX.prototype.toJSON = function toJSON() {
  // Compact representation
  return {
    v: '1',
    type: 'tx',
    ts: this.ts,
    ps: this.ps,
    block: this.block,
    tx: utils.toHex(this.render())
  };
};

TX.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'tx');

  var raw = utils.toArray(json.tx, 'hex');
  var tx = new TX(new bcoin.protocol.parser().parseTX(raw));
  tx.ts = json.ts;
  tx.block = json.block || null;
  tx.ps = json.ps;

  return tx;
};

TX.prototype.clone = function clone() {
  return new TX(new bcoin.protocol.parser().parseTX(this.render()));
};

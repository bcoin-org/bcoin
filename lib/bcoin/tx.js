var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

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

TX.prototype.signature = function(input, key) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(tx.inputs.indexOf(input), s, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(constants.hashType[type]);

  return signature;
};

// Build the scriptSigs for inputs, excluding the signatures
TX.prototype.scriptInput = function(input, pub, nsigs) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // P2PKH and simple tx
  if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
    input.script = [ constants.opcodes['0'], pub ];
    return;
  }

  // Multisig
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  if (bcoin.script.isMultisig(s)) {
    if (!nsigs) {
      throw new Error('`nsigs` is required for multisig');
    }
    input.script = [ constants.opcodes['false'] ];
    for (var i = 0; i < nsigs; i++) {
      input.script[i + 1] = constants.opcodes['0'];
    }
    return;
  }

  // P2SH multisig
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isScripthash(s)) {
    input.script = [ constants.opcodes['false'] ];
    var m = pub[0] - constants.opcodes['1'] + 1;
    for (var i = 0; i < m; i++) {
      input.script[i + 1] = constants.opcodes['0'];
    }
    // P2SH requires the redeem script after signatures
    if (bcoin.script.isScripthash(s)) {
      input.script.push(pub);
    }
    return;
  }

  throw new Error('could not identify prev_out type');
};

// Sign the now-built scriptSigs
TX.prototype.signInput = function(input, key) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(tx.inputs.indexOf(input), s, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(constants.hashType[type]);

  // P2PKH and simple tx
  if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
    input.script[0] = signature;
    return;
  }

  // Multisig
  // empty array == OP_FALSE == OP_0
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isMultisig(s) || bcoin.script.isScripthash(s)) {
    var l = input.script.length;
    if (bcoin.script.isScripthash(s)) {
      l--;
    }
    for (var i = 0; i < l; i++) {
      input.script[i + 1] = signature;
    }
  }
};

// Build the scriptSig and sign it
TX.prototype.scriptSig = function(input, key, pub, nsigs) {
  // Build script for input
  tx.scriptInput(input, pub, nsigs);

  // Sign input
  tx.signInput(input, key);

  return this.input.script;
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

  if (Array.isArray(output.keys || output.address)) {
    // Raw multisig transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // [required-sigs] [pubkey-hash1] [pubkey-hash2] ... [number-of-keys] checkmultisig
    var keys = output.keys || output.address;
    if (keys === output.address) {
      keys = keys.map(function(address) {
        return bcoin.wallet.addr2hash(address);
      });
    }
    keys = keys.map(function(key) {
      if (typeof key === 'string') {
        return utils.toKeyArray(key);
      }
      return key;
    });
    script = [
      [ output.minSignatures || keys.length ]
    ].concat(
      keys,
      [ [ keys.length ], 'checkmultisig' ]
    );
    // outputs: [ [ 2 ], 'key1', 'key2', [ 2 ], 'checkmultisig' ]
    // in reality:
    // outputs: [ [ 2 ], [0,1,...], [2,3,...], [ 2 ], 'checkmultisig' ]
  } else if (bcoin.wallet.validateAddress(output.address, 'p2sh')) {
    // p2sh transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    // hash160 [20-byte-redeemscript-hash] equal
    script = [
      'hash160',
      bcoin.wallet.addr2hash(output.address, 'p2sh'),
      'eq'
    ];
  } else if (output.address) {
    // p2pkh transaction
    // dup hash160 [pubkey-hash] equalverify checksig
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

    // XXX Deal with different hashTypes besides `all`
    // var hash = this.subscriptHash.bind(this, i, subscript);

    var stack = [];
    bcoin.script.execute(input.script, stack);
    var prev = input.out.tx.outputs[input.out.index].script;
    var res = bcoin.script.execute(prev, stack, hash);
    if (!res)
      return false;

    return stack.length > 0 && utils.isEqual(stack.pop(), [ 1 ]);
  }, this);
};

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && +this.inputs[0].out.hash === 0;
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

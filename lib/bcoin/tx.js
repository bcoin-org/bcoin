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

  this.change = data.change || null;
  this.fee = data.fee || 10000;
  this.dust = 5460;
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
  this._input(i, index);
  return this;
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
    input.out.tx = input.out.tx || ex.out.tx;
    input.seq = input.seq || ex.seq;
    input.script = input.script.length ? input.script : ex.script;
    this.inputs[index] = input;
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

TX.prototype.signature = function(input, key, type) {
  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = bcoin.protocol.constants.hashType[type];

  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(tx.inputs.indexOf(input), s, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(type);

  return signature;
};

// Build the scriptSigs for inputs, excluding the signatures
TX.prototype.scriptInput = function(input, pub, nsigs) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // P2PKH and simple tx
  if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
    input.script = [ [], pub ];
    return;
  }

  // Multisig
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  if (bcoin.script.isMultisig(s)) {
    input.script = [ [] ];
    var m = s[0];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(m))
      m = m[0];
    for (var i = 0; i < m; i++)
      input.script[i + 1] = [];
    return;
  }

  // P2SH multisig
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isScripthash(s)) {
    input.script = [ [] ];
    var m = pub[0] - constants.opcodes['1'] + 1;
    for (var i = 0; i < m; i++)
      input.script[i + 1] = [];
    // P2SH requires the redeem script after signatures
    input.script.push(pub);
    return;
  }

  throw new Error('scriptInput(): could not identify prev_out type');
};

// Sign the now-built scriptSigs
TX.prototype.signInput = function(input, key, type) {
  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = bcoin.protocol.constants.hashType[type];

  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(this.inputs.indexOf(input), s, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(type);

  // P2PKH and simple tx
  if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
    input.script[0] = signature;
    return;
  }

  // Multisig
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isMultisig(s) || bcoin.script.isScripthash(s)) {
    var len = input.script.length;

    if (bcoin.script.isScripthash(s))
      len--;

    for (var i = 1; i < len; i++) {
      // Already signed
      if (utils.isEqual(input.script[i], signature))
        break;

      if (input.script[i].length === 0) {
        input.script[i] = signature;
        break;
      }
    }
    return;
  }

  throw new Error('signInput(): could not identify prev_out type');
};

// Build the scriptSig and sign it
TX.prototype.scriptSig = function(input, key, pub, type, nsigs) {
  // Build script for input
  this.scriptInput(input, pub, nsigs);

  // Sign input
  this.signInput(input, key, type);

  return input.script;
};

TX.prototype.output = function output(output, value) {
  if (output instanceof bcoin.wallet)
    output = output.getAddress();

  if (typeof output === 'string') {
    output = {
      address: output,
      value: value
    };
  }

  this.outputs.push({
    value: new bn(output.value),
    script: this.scriptOutput(output)
  });

  return this;
};

// compat
TX.prototype.out = TX.prototype.output;

TX.prototype.scriptOutput = function(options) {
  var script = options.script ? options.script.slice() : [];

  if (Array.isArray(options.keys || options.address)) {
    // Raw multisig transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // [required-sigs] [pubkey-hash1] [pubkey-hash2] ... [number-of-keys] checkmultisig
    var keys = options.keys || options.address;

    if (keys === options.address) {
      keys = keys.map(function(address) {
        return bcoin.wallet.addr2hash(address, 'normal');
      });
    }

    keys = keys.map(function(key) {
      if (typeof key === 'string')
        return utils.toKeyArray(key);
      return key;
    });

    // compat:
    options.m = options.minSignatures || options.m;
    var m = options.m || keys.length;
    var n = options.n || keys.length;

    assert(m >= 1 && m <= n);
    if (options.hash)
      assert(n >= 1 && n <= 7);
    else
      assert(n >= 1 && n <= 3);

    script = bcoin.script.multisig(keys, m, n);
  } else if (bcoin.wallet.validateAddress(options.address, 'p2sh')) {
    // p2sh transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    // hash160 [20-byte-redeemscript-hash] equal
    script = [
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'p2sh'),
      'eq'
    ];
  } else if (options.address) {
    // p2pkh transaction
    // dup hash160 [pubkey-hash] equalverify checksig
    script = [
      'dup',
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'normal'),
      'eqverify',
      'checksig'
    ];
  }

  // make it p2sh
  if (options.hash) {
    var redeem = script;
    var hash = utils.ripesha(bcoin.script.encode(redeem));
    script = [
      'hash160',
      hash,
      'eq'
    ];
    script.redeem = redeem;
  }

  return script;
};

TX.prototype.getSubscript = function getSubscript(index) {
  var output = this.outputs[index];
  assert(output);

  var script = output.script;
  return bcoin.script.subscript(script);
};

TX.prototype.subscriptHash = function subscriptHash(index, s, type) {
  var copy = this.clone();

  if (typeof type === 'string')
    type = bcoin.protocol.constants.hashType[type];

  copy.inputs.forEach(function(input, i) {
    input.script = index === i ? s : [];
  });
  var verifyStr = copy.render();
  utils.writeU32(verifyStr, type, verifyStr.length);
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
    var hasher = this.subscriptHash.bind(this, i, subscript);

    var stack = [];
    bcoin.script.execute(input.script, stack);
    var prev = input.out.tx.outputs[input.out.index].script;
    var res = bcoin.script.execute(prev, stack, hasher);
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
    // Get the previous output's script
    // var s = input.out.tx.outputs[input.out.index].script;

    // Get the previous output's subscript
    var s = input.out.tx.getSubscript(input.out.index);

    if (bcoin.script.isPubkeyhash(s) || bcoin.script.isSimplePubkeyhash(s)) {
      // Signature + len
      size += 74;
      // Pub key + len
      size += 34;
      return;
    }

    if (bcoin.script.isMultisig(s)) {
      // Multisig
      // Empty byte
      size += 1;
      // Signature + len
      var m = s[0];
      // If using pushdata instead of OP_1-16:
      if (Array.isArray(m))
        m = m[0];
      assert(m >= 1 && m <= 3);
      size += 74 * m;
      return;
    }

    if (bcoin.script.isScripthash(s)) {
      var script = this.inputs[i].script;
      var redeem, m, n;
      if (script) {
        redeem = script[script.length - 1];
        m = redeem[0];
        n = redeem[redeem.length - 2];
        // If using pushdata instead of OP_1-16:
        if (Array.isArray(m))
          m = m[0];
        if (Array.isArray(n))
          n = n[0];
      } else {
        // May end up in a higher fee if we
        // do not have the redeem script available.
        m = 7;
        n = 7;
      }
      assert(m >= 1 && m <= n);
      assert(n >= 1 && n <= 7);
      // Multisig
      // Empty byte
      size += 1;
      // Signature + len
      size += 74 * m;
      // Redeem script
      // m byte
      size += 1;
      // 1 byte length + 65 byte pubkey
      size += 66 * n;
      // n byte
      size += 1;
      // checkmultisig byte
      size += 1;
      return;
    }
  }, this);

  return size;
};

// Building a TX:
// 1. Add outputs:
//   - this.output({ address: ..., value: ... });
//   - this.output({ address: ..., value: ... });
// 2. Add inputs with utxos and change output:
//   - this.fillUnspent(unspentItems, [changeAddr]);
// 3. Fill input scripts (for each input):
//   - this.scriptInput(input, pub, [nsigs])
//   - this.signInput(input, key, [sigHashType])
TX.prototype.utxos = function utxos(unspent) {
  // NOTE: tx should be prefilled with all outputs
  var cost = this.funds('out');

  // Use initial fee for starters
  var fee = 1;

  // total = cost + fee
  var total = cost.add(new bn(this.fee));

  var inputs = this.inputs.slice();
  var utxos = [];

  var lastAdded = 0;
  function addInput(unspent, i) {
    // Add new inputs until TX will have enough funds to cover both
    // minimum post cost and fee
    var index = this._input(unspent);
    utxos.push(this.inputs[index]);
    lastAdded++;
    return this.funds('in').cmp(total) < 0;
  }

  // Transfer `total` funds maximum
  // var unspent = wallet.unspent();
  unspent.every(addInput, this);

  // Add dummy output (for `left`) to calculate maximum TX size
  this.output({ address: null, value: new bn(0) });

  // Change fee value if it is more than 1024 bytes
  // (10000 satoshi for every 1024 bytes)
  do {
    // Calculate maximum possible size after signing
    var byteSize = this.maxSize();

    var addFee = Math.ceil(byteSize / 1024) - fee;
    total.iadd(new bn(addFee * this.fee));
    fee += addFee;

    // Failed to get enough funds, add more inputs
    if (this.funds('in').cmp(total) < 0)
      unspent.slice(lastAdded).every(addInput, this);
  } while (this.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

  // Still failing to get enough funds
  if (this.funds('in').cmp(total) < 0) {
    this.inputs = inputs;
    this.outputs.pop();
    this.cost = total;
    return null;
  }

  // How much money is left after sending outputs
  var left = this.funds('in').sub(total);

  // Clear the tx of everything we added.
  this.inputs = inputs;
  this.outputs.pop();
  this.cost = total;

  // Return necessary utxos and change.
  return {
    utxos: utxos,
    change: left,
    cost: total
  };
};

TX.prototype.fillUnspent = function fillUnspent(unspent, change) {
  var result = this.utxos(unspent);

  if (!result)
    return result;

  result.utxos.forEach(function(utxo) {
    this.input(utxo, null);
  }, this);

  // Not enough money, transfer everything to owner
  if (result.change.cmpn(this.dust) < 0) {
    // NOTE: that this output is either `postCost` or one of the `dust` values
    this.outputs[this.outputs.length - 1].value.iadd(result.change);
  } else {
    this.output({
      address: change || this.change,
      value: result.change
    });
  }

  return result;
};

TX.prototype.inputAddrs = function inputAddrs() {
  return this.inputs.filter(function(input) {
    return bcoin.script.isPubkeyhashInput(input.script);
  }).map(function(input) {
    var pub = input.script[1];
    var hash = utils.ripesha(pub);
    return bcoin.wallet.hash2addr(hash, 'normal');
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

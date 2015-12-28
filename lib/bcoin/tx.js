/**
 * tx.js - transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * TX
 */

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
  this._size = data._size || 0;

  this.network = data.network || false;
  this.relayedBy = data.relayedBy || '0.0.0.0';
  this._height = data._height != null ? data._height : -1;
  this._confirmations = data._confirmations != null ? data._confirmations : -1;

  this._lock = this.lock;

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

  if (block && block.subtype === 'merkleblock') {
    if (!data.ts && block && block.hasTX(this.hash('hex'))) {
      this.ts = block.ts;
      this.block = block.hash('hex');
    }
  }

  this.changeAddress = data.changeAddress || null;
  this.changeOutput = data.changeOutput || null;

  // ps = Pending Since
  this.ps = this.ts === 0 ? +new Date() / 1000 : 0;
}

TX.fee = 10000;
TX.dust = 5460;

TX.prototype.clone = function clone() {
  return new TX(this);
};

TX.prototype.hash = function hash(enc) {
  var h = utils.dsha256(this.render());
  return enc === 'hex' ? utils.toHex(h) : h;
};

TX.prototype.render = function render() {
  if (this.network && this._raw)
    return this._raw.slice();
  return bcoin.protocol.framer.tx(this);
};

TX.prototype.size = function size() {
  return this._size || this.render().length;
};

TX.prototype.input = function input(i, index) {
  this._input(i, index);
  return this;
};

TX.prototype._input = function _input(obj, index) {
  var options, hash, input, ex, i;

  if (obj instanceof TX)
    options = { tx: obj, index: index };
  else if (typeof obj === 'string' || Array.isArray(obj))
    options = { hash: obj, index: index };
  else
    options = obj;

  if (options.tx)
    hash = options.tx.hash('hex');
  else if (options.out)
    hash = options.out.hash;
  else
    hash = options.hash;

  if (typeof hash !== 'string')
    hash = utils.toHex(hash);

  input = bcoin.input({
    tx: this,
    out: {
      tx: options.out ? options.out.tx : options.tx,
      hash: hash,
      index: options.out ? options.out.index : options.index
    },
    script: options.script,
    seq: options.seq
  });

  // Try modifying existing input first
  i = this._inputIndex(hash, index);
  if (i !== -1) {
    ex = this.inputs[i];
    input.out.tx = input.out.tx || ex.out.tx;
    input.seq = input.seq || ex.seq;
    input.script = input.script.length ? input.script : ex.script;
    this.inputs[i] = input;
  } else {
    this.inputs.push(input);
    i = this.inputs.length - 1;
  }

  return i;
};

TX.prototype._inputIndex = function _inputIndex(hash, index) {
  var i, ex;

  if (hash instanceof TX)
    hash = hash.hash('hex');

  for (i = 0; i < this.inputs.length; i++) {
    ex = this.inputs[i];
    if (ex.out.hash === hash && ex.out.index === index)
      return i;
  }

  return -1;
};

// Build the scriptSigs for inputs, excluding the signatures
TX.prototype.scriptInput = function scriptInput(input, pub) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);
  var n, i, redeem;

  // Already has a script template (at least)
  if (input.script.length)
    return;

  // P2PK
  if (bcoin.script.isPubkey(s)) {
    input.script = [ [] ];
    this._recalculateFee();
    return;
  }

  // P2PKH
  if (bcoin.script.isPubkeyhash(s)) {
    input.script = [ [], pub ];
    this._recalculateFee();
    return;
  }

  // NOTE for multisig: Technically we should create m signature slots,
  // but we create n signature slots so we can order the signatures properly.

  // Multisig
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  if (bcoin.script.isMultisig(s)) {
    input.script = [ [] ];
    n = s[s.length - 2];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(n))
      n = n[0] || 0;
    for (i = 0; i < n; i++)
      input.script[i + 1] = [];
    this._recalculateFee();
    return;
  }

  // P2SH multisig
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isScripthash(s)) {
    input.script = [ [] ];
    redeem = bcoin.script.decode(pub);
    n = redeem[redeem.length - 2];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(n))
      n = n[0] || 0;
    for (i = 0; i < n; i++)
      input.script[i + 1] = [];
    // P2SH requires the redeem script after signatures
    input.script.push(pub);
    this._recalculateFee();
    return;
  }

  throw new Error('scriptInput(): Could not identify prev_out type');
};

// Sign the now-built scriptSigs
TX.prototype.signInput = function signInput(input, key, type) {
  var s, hash, signature;
  var len, redeem, m, keys, pub, pubn, ki, totalSigs, i;

  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the previous output's subscript
  s = input.out.tx.getSubscript(input.out.index);

  if (bcoin.script.isScripthash(s)) {
    // We need to grab the redeem script when signing p2sh transactions.
    redeem = bcoin.script.decode(input.script[input.script.length - 1]);
  } else {
    redeem = s;
  }

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  hash = this.subscriptHash(this.inputs.indexOf(input), redeem, type);

  // Sign the transaction with our one input
  signature = bcoin.ecdsa.sign(hash, key.priv).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(type);

  // P2PK
  if (bcoin.script.isPubkey(s)) {
    input.script[0] = signature;
    return;
  }

  // P2PKH
  if (bcoin.script.isPubkeyhash(s)) {
    input.script[0] = signature;
    return;
  }

  // Multisig
  // raw format: OP_FALSE [sig-1] [sig-2] ...
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isMultisig(s) || bcoin.script.isScripthash(s)) {
    len = input.script.length;

    if (bcoin.script.isScripthash(s))
      len--;

    m = redeem[0];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(m))
      m = m[0] || 0;

    keys = redeem.slice(1, -2);
    pub = key.getPublic(true, 'array');
    pubn = key.getPublic(false, 'array');

    // Find the key index so we can place
    // the signature in the same index.
    for (ki = 0; ki < keys.length; ki++) {
      if (utils.isEqual(pub, keys[ki]) || utils.isEqual(pubn, keys[ki]))
        break;
    }

    // Public key is not in the prev_out script
    if (ki === keys.length)
      return;

    // No signature slot available
    if (ki + 1 > len - 1)
      return;

    // Add our signature to the correct slot
    // and count the total number of signatures.
    totalSigs = 0;
    for (i = 1; i < len; i++) {
      if (Array.isArray(input.script[i]) && input.script[i].length) {
        totalSigs++;
        continue;
      }

      if (i - 1 === ki) {
        if (totalSigs >= m)
          continue;
        input.script[i] = signature;
        totalSigs++;
      }
    }

    // All signatures added. Finalize by removing empty slots.
    if (totalSigs >= m) {
      for (i = len - 1; i >= 1; i--) {
        if (Array.isArray(input.script[i]) && !input.script[i].length)
          input.script.splice(i, 1);
      }
    }

    return;
  }

  throw new Error('signInput(): Could not identify prev_out type');
};

// Build the scriptSig and sign it
TX.prototype.scriptSig = function scriptSig(input, key, pub, type) {
  if (!Array.isArray(pub)) {
    type = pub;
    pub = key.getPublic(true, 'array');
  }

  // Build script for input
  this.scriptInput(input, pub);

  // Sign input
  this.signInput(input, key, type);

  return input.script;
};

TX.prototype.output = function output(obj, value) {
  var options;

  if (obj instanceof bcoin.wallet)
    obj = obj.getAddress();

  if (typeof obj === 'string') {
    options = {
      address: obj,
      value: value
    };
  } else {
    options = obj;
  }

  var output = bcoin.output({
    tx: this,
    value: options.value,
    script: options.script
  });

  this.outputs.push(output);

  this.scriptOutput(output, options);

  return this;
};

// compat
TX.prototype.out = TX.prototype.output;

TX.prototype.scriptOutput = function scriptOutput(output, options) {
  options = options || output;

  var script = output.script;
  var keys, m, n, hash, color;

  if (Array.isArray(options.keys || options.address)) {
    // Raw multisig transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // [required-sigs] [pubkey-hash1] [pubkey-hash2] ... [number-of-keys] checkmultisig
    keys = options.keys || options.address;

    if (keys === options.address) {
      keys = keys.map(function(address) {
        return bcoin.wallet.addr2hash(address, 'pubkeyhash');
      });
    }

    keys = keys.map(function(key) {
      if (typeof key === 'string')
        return utils.toKeyArray(key);
      return key;
    });

    // compat:
    options.m = options.minSignatures || options.m;
    m = options.m || keys.length;
    n = options.n || keys.length;

    assert(m >= 1 && m <= n);
    if (options.scripthash)
      assert(n >= 1 && n <= 15);
    else
      assert(n >= 1 && n <= 3);

    script = bcoin.script.redeem(keys, m, n);

    // make it p2sh
    if (options.scripthash) {
      hash = utils.ripesha(bcoin.script.encode(script));
      script = [
        'hash160',
        hash,
        'eq'
      ];
    }
  } else if (bcoin.wallet.validateAddress(options.address, 'scripthash')) {
    // p2sh transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    // hash160 [20-byte-redeemscript-hash] equal
    script = [
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'scripthash'),
      'eq'
    ];
  } else if (options.address) {
    // p2pkh transaction
    // dup hash160 [pubkey-hash] equalverify checksig
    script = [
      'dup',
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'pubkeyhash'),
      'eqverify',
      'checksig'
    ];
  } else if (options.color) {
    color = options.color;
    if (typeof color === 'string')
      color = utils.ascii2array(color);
    assert(color.length <= 40);
    script = [
      'ret',
      color
    ];
  }

  output.script = script;
};

TX.prototype.getSubscript = function getSubscript(index) {
  var script = this.outputs[index].script;
  return bcoin.script.subscript(script);
};

TX.prototype.subscriptHash = function subscriptHash(index, s, type) {
  var copy = this.clone();
  var verifyStr, hash;

  if (typeof type === 'string')
    type = constants.hashType[type];

  // bitcoind used to return 1 as an error code:
  // it ended up being treated like a hash.
  if (index >= copy.inputs.length)
    return constants.oneHash.slice();

  copy.inputs.forEach(function(input, i) {
    input.script = index === i ? s : [];
  });

  if ((type & 0x1f) === constants.hashType.all) {
    ;
  } else if ((type & 0x1f) === constants.hashType.none) {
    copy.outputs = [];
    copy.inputs.forEach(function(input, i) {
      if (i !== index)
        input.seq = 0;
    });
  } else if ((type & 0x1f) === constants.hashType.single) {
    // bitcoind sighash_single bug:
    if (index >= copy.outputs.length)
      return constants.oneHash.slice();
    while (copy.outputs.length < index + 1)
      copy.outputs.push({});
    while (copy.outputs.length > index + 1)
      copy.outputs.pop();
    copy.outputs.forEach(function(output, i) {
      if (i !== index) {
        output.script = [];
        output.value = utils.toArray('ffffffffffffffff', 'hex');
        output.value.toArray = function() { return this; };
      }
    });
    copy.inputs.forEach(function(input, i) {
      if (i !== index)
        input.seq = 0;
    });
  }

  if (type & constants.hashType.anyonecanpay) {
    copy.inputs.length = 1;
    copy.inputs[0].script = s;
  }

  verifyStr = copy.render();

  utils.writeU32(verifyStr, type, verifyStr.length);

  hash = utils.dsha256(verifyStr);

  return hash;
};

TX.prototype.verify = function verify(index, force) {
  // Valid if included in block
  if (!force && this.ts !== 0)
    return true;

  if (this.inputs.length === 0)
    return false;

  return this.inputs.every(function(input, i) {
    var stack, prev, push, res, redeem;

    if (index !== undefined && index !== i)
      return true;

    if (!input.out.tx)
      return false;

    assert(input.out.tx.outputs.length > input.out.index);

    stack = [];
    prev = input.out.tx.outputs[input.out.index].script;

    if (bcoin.script.isScripthash(prev)) {
      // p2sh transactions cannot have anything
      // other than pushdata ops in the scriptSig
      push = input.script.slice(1).every(Array.isArray);
      if (!push)
        return false;
    }

    bcoin.script.execute(input.script, stack, this, i);
    res = bcoin.script.execute(prev, stack, this, i);

    if (!res || stack.length === 0 || new bn(stack.pop()).cmpn(0) === 0)
      return false;

    if (bcoin.script.isScripthash(prev)) {
      redeem = input.script[input.script.length - 1];
      if (!Array.isArray(redeem))
        return false;
      redeem = bcoin.script.decode(redeem);
      res = bcoin.script.execute(redeem, stack, this, i);
      if (!res || stack.length === 0 || new bn(stack.pop()).cmpn(0) === 0)
        return false;
    }

    return true;
  }, this);
};

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && +this.inputs[0].out.hash === 0;
};

TX.prototype.maxSize = function maxSize() {
  // Create copy with 0-script inputs
  var copy = this.clone();
  var size;

  copy.inputs.forEach(function(input) {
    input.script = [];
  });

  size = copy.render().length;

  // Add size for signatures and public keys
  copy.inputs.forEach(function(input, i) {
    var s, m, n, script, redeem;

    // Get the previous output's subscript
    s = input.out.tx.getSubscript(input.out.index);

    if (bcoin.script.isPubkey(s)) {
      // Signature + len
      size += 74;
      return;
    }

    if (bcoin.script.isPubkeyhash(s)) {
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
      m = s[0];
      // If using pushdata instead of OP_1-16:
      if (Array.isArray(m))
        m = m[0] || 0;
      assert(m >= 1 && m <= 3);
      size += 74 * m;
      return;
    }

    if (bcoin.script.isScripthash(s)) {
      script = this.inputs[i].script;
      if (script.length) {
        redeem = bcoin.script.decode(script[script.length - 1]);
        m = redeem[0];
        n = redeem[redeem.length - 2];
        // If using pushdata instead of OP_1-16:
        if (Array.isArray(m))
          m = m[0] || 0;
        if (Array.isArray(n))
          n = n[0] || 0;
      } else {
        // May end up in a higher fee if we
        // do not have the redeem script available.
        m = 15;
        n = 15;
      }
      assert(m >= 1 && m <= n);
      assert(n >= 1 && n <= 15);
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

TX.prototype.getUnspent = function getUnspent(unspent) {
  var tx = this.clone();

  // NOTE: tx should be prefilled with all outputs
  var cost = tx.funds('out');

  // Use initial fee for starters
  var fee = 1;

  // total = cost + fee
  var total = cost.addn(TX.fee);

  var inputs = [];

  var lastAdded = 0;

  var byteSize, addFee, change;

  function addInput(unspent) {
    // Add new inputs until TX will have enough funds to cover both
    // minimum post cost and fee
    var index = tx._input(unspent);
    inputs.push(tx.inputs[index]);
    lastAdded++;
    return tx.funds('in').cmp(total) < 0;
  }

  // Transfer `total` funds maximum
  // var unspent = wallet.unspent();
  unspent.every(addInput);

  // Add dummy output (for `change`) to calculate maximum TX size
  tx.output({ address: null, value: new bn(0) });

  // Change fee value if it is more than 1024 bytes
  // (10000 satoshi for every 1024 bytes)
  do {
    // Calculate maximum possible size after signing
    byteSize = tx.maxSize();

    addFee = Math.ceil(byteSize / 1024) - fee;
    total.iaddn(addFee * TX.fee);
    fee += addFee;

    // Failed to get enough funds, add more inputs
    if (tx.funds('in').cmp(total) < 0)
      unspent.slice(lastAdded).every(addInput);
  } while (tx.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

  // Still failing to get enough funds
  if (tx.funds('in').cmp(total) < 0) {
    this.total = total;
    return null;
  }

  // How much money is left after sending outputs
  change = tx.funds('in').sub(total);

  this.total = total;

  // Return necessary inputs and change.
  return {
    inputs: inputs,
    change: change,
    cost: cost,
    fee: total.sub(cost),
    total: total
  };
};

TX.prototype.fillUnspent = function fillUnspent(unspent, changeAddress) {
  var result = unspent.cost ? unspent : this.getUnspent(unspent);

  if (!result)
    return result;

  this.changeAddress = changeAddress
    || this.changeAddress
    || result.inputs[0].output.addr;

  result.inputs.forEach(function(input) {
    this.input(input);
  }, this);

  if (result.change.cmpn(TX.dust) < 0) {
    // Do nothing. Change is added to fee.
    assert.equal(
      this.getFee().toNumber(),
      result.fee.add(result.change).toNumber()
    );
    this.changeOutput = null;
  } else {
    if (!this.changeAddress)
      throw new Error('No change address');
    this.output({
      address: this.changeAddress,
      value: result.change
    });
    this.changeOutput = this.outputs[this.outputs.length - 1];
  }

  return result;
};

TX.prototype._recalculateFee = function recalculateFee() {
  var output = this.changeOutput;

  if (!output) {
    this.output({
      address: this.changeAddress,
      value: new bn(0)
    });
    output = this.outputs[this.outputs.length - 1];
  }

  var byteSize = this.maxSize();
  var newFee = Math.ceil(byteSize / 1024) * TX.fee;
  var currentFee = this.getFee().toNumber();

  if (newFee === currentFee) {
    if (!this.changeOutput)
      this.outputs.pop();
    return;
  }

  if (newFee > currentFee) {
    if (output.value.cmpn(newFee - currentFee) < 0) {
      this.outputs.pop();
      this.changeOutput = null;
      return;
    }
    output.value.isubn(newFee - currentFee);
  } else {
    output.value.iaddn(currentFee - newFee);
  }

  if (output.value.cmpn(TX.dust) < 0) {
    this.outputs.pop();
    this.changeOutput = null;
    return;
  }

  this.changeOutput = output;
};

TX.prototype.getFee = function getFee() {
  if (this.funds('in').cmp(this.funds('out')) < 0)
    return new bn(0);

  return this.funds('in').sub(this.funds('out'));
};

TX.prototype.funds = function funds(side) {
  var acc = new bn(0);
  var inputs;

  if (side === 'in') {
    inputs = this.inputs.filter(function(input) {
      return input.out.tx;
    });

    if (inputs.length === 0)
      return acc;

    inputs.reduce(function(acc, input) {
      return acc.iadd(input.out.tx.outputs[input.out.index].value);
    }, acc);

    return acc;
  }

  // Output
  if (this.outputs.length === 0)
    return acc;

  this.outputs.reduce(function(acc, output) {
    return acc.iadd(output.value);
  }, acc);

  return acc;
};

TX.prototype.getHeight = function getHeight(chain) {
  if (this._height >= 0)
    return this._height;

  chain = chain || bcoin.chain.global;

  if (!chain)
    return -1;

  this._height = this.block ? chain.getHeight(this.block) : -1;

  return this._height;
};

TX.prototype.getConfirmations = function getConfirmations(chain) {
  var top, height;

  if (this._confirmations >= 0)
    return this._confirmations;

  chain = chain || bcoin.chain.global;

  if (!chain)
    return 0;

  top = chain.index.heights[chain.index.heights.length - 1];
  height = this.getHeight(chain);

  if (height === -1)
    return 0;

  return top - height + 1;
};

TX.prototype.__defineGetter__('rblock', function() {
  return this.block
    ? utils.revHex(this.block)
    : null;
});

TX.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

TX.prototype.__defineGetter__('fee', function() {
  return this.getFee();
});

TX.prototype.__defineGetter__('value', function() {
  return this.funds('in');
});

TX.prototype.__defineSetter__('height', function(height) {
  return this._height = height;
});

TX.prototype.__defineGetter__('height', function() {
  return this.getHeight(bcoin.chain.global);
});

TX.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations(bcoin.chain.global);
});

TX.prototype.inspect = function inspect() {
  var copy = bcoin.tx(this);
  copy.__proto__ = null;
  if (this.block)
    copy.block = this.block;
  delete copy._raw;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.rblock = this.rblock;
  copy.value = utils.btc(this.value);
  copy.fee = utils.btc(this.fee);
  copy.height = this.height;
  copy.confirmations = this.confirmations;
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

TX.prototype.toJSON = function toJSON() {
  // Compact representation
  return {
    v: '1',
    type: 'tx',
    ts: this.ts,
    ps: this.ps,
    block: this.block,
    network: this.network,
    relayedBy: this.relayedBy,
    tx: utils.toHex(this.render())
  };
};

TX.fromJSON = function fromJSON(json) {
  var raw, data, tx;

  assert.equal(json.v, 1);
  assert.equal(json.type, 'tx');

  raw = utils.toArray(json.tx, 'hex');
  data = new bcoin.protocol.parser().parseTX(raw);

  data.network = json.network;
  data.relayedBy = json.relayedBy;

  tx = new TX(data);
  tx.ts = json.ts;
  tx.block = json.block || null;
  tx.ps = json.ps;

  return tx;
};

/**
 * Expose
 */

module.exports = TX;

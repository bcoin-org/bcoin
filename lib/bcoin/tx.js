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

  this._chain = data.chain;

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
  this.ps = this.ts === 0 ? utils.now() : 0;
}

TX.prototype.clone = function clone() {
  return new TX(this);
};

TX.prototype.hash = function hash(enc) {
  var h = utils.dsha256(this.render());
  return enc === 'hex' ? utils.toHex(h) : h;
};

TX.prototype.render = function render(force) {
  if (!force && this.network && this._raw)
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
  else if (typeof obj === 'string' || utils.isBuffer(obj))
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
  i = this._inputIndex(input.out.hash, input.out.index);
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
TX.prototype.scriptInput = function scriptInput(index, pub, redeem) {
  var input, s, n, i;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.out.tx);

  // Already has a script template (at least)
  if (input.script.length)
    return;

  // Get the previous output's subscript
  s = input.out.tx.getSubscript(input.out.index);

  // P2SH
  if (bcoin.script.isScripthash(s)) {
    assert(redeem);
    s = bcoin.script.normalize(redeem);
  } else {
    redeem = null;
  }

  if (bcoin.script.isPubkey(s)) {
    // P2PK
    input.script = [ [] ];
  } else if (bcoin.script.isPubkeyhash(s)) {
    // P2PKH
    input.script = [ [], pub ];
  } else if (bcoin.script.isMultisig(s)) {
    // Bare Multisig
    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    input.script = [ [] ];

    // Grab `n` value (number of keys).
    n = s[s.length - 2];
    if (Array.isArray(n))
      n = n[0];

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      input.script[i + 1] = [];
  }

  // P2SH requires the redeem script after signatures
  if (redeem)
    input.script.push(redeem);

  this._recalculateFee();
};

// Sign the now-built scriptSigs
TX.prototype.signInput = function signInput(index, key, type) {
  var input, s, hash, signature;
  var len, redeem, m, n, keys, pub, pkh, ki, signatures, i;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (type == null)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.out.tx);

  // Get the previous output's subscript
  s = input.out.tx.getSubscript(input.out.index);

  if (bcoin.script.isScripthash(s)) {
    // We need to grab the redeem script when
    // signing p2sh transactions.
    redeem = bcoin.script.decode(input.script[input.script.length - 1]);
  } else {
    redeem = s;
  }

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, redeem, type);

  // Sign the transaction with our one input
  signature = bcoin.ecdsa.sign(hash, key.priv).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(type);

  // Get pubkey and pubkey hash.
  pub = key.getPublic(true, 'array');
  pkh = bcoin.wallet.key2hash(pub);

  // Script length, needed for multisig
  len = input.script.length;

  // P2SH
  if (bcoin.script.isScripthash(s)) {
    s = bcoin.script.normalize(redeem);
    // Decrement `len` to avoid the redeem script
    len--;
  }

  // Add signatures.
  if (bcoin.script.isPubkey(s)) {
    // P2PK

    // Something is wrong. Abort.
    if (!Array.isArray(input.script[0]))
      return false;

    // Already signed.
    if (input.script[0].length)
      return true;

    // Make sure the pubkey is ours.
    if (!utils.isEqual(pub, s[0]))
      return false;

    input.script[0] = signature;

    return true;
  } else if (bcoin.script.isPubkeyhash(s)) {
    // P2PKH

    // Something is wrong. Abort.
    if (!Array.isArray(input.script[0]))
      return false;

    // Already signed.
    if (input.script[0].length)
      return true;

    // Make sure the pubkey hash is ours.
    if (!utils.isEqual(pkh, s[2]))
      return false;

    input.script[0] = signature;

    return true;
  } else if (bcoin.script.isMultisig(s)) {
    // Multisig

    // Grab `m` value (number of sigs required).
    m = s[0];
    if (Array.isArray(m))
      m = m[0];

    // Grab `n` value (number of keys).
    n = s[s.length - 2];
    if (Array.isArray(n))
      n = n[0];

    // Something is very wrong here. Abort.
    if (len - 1 > n)
      return;

    // Count the number of current signatures.
    signatures = 0;
    for (i = 1; i < len; i++) {
      if (Array.isArray(input.script[i]) && input.script[i].length)
        signatures++;
    }

    // Signatures are already finalized.
    if (signatures === m && len - 1 === m)
      return;

    // This can happen in a case where another
    // implementation adds signatures willy-nilly
    // or by `m`. Add some signature slots for
    // us to use.
    while (len - 1 < n) {
      input.script.splice(len, 0, []);
      len++;
    }

    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = s.slice(1, -2);

    // Find the key index so we can place
    // the signature in the same index.
    for (ki = 0; ki < keys.length; ki++) {
      if (utils.isEqual(pub, keys[ki]))
        break;
    }

    // Our public key is not in the prev_out
    // script. We tried to sign a transaction
    // that is not redeemable by us.
    if (ki === keys.length)
      return;

    // Offset key index by one to turn it into
    // "sig index". Accounts for OP_0 byte at
    // the start.
    ki++;

    // Add our signature to the correct slot
    // and increment the total number of
    // signatures.
    if (ki < len && signatures < m) {
      if (Array.isArray(input.script[ki]) && !input.script[ki].length) {
        input.script[ki] = signature;
        signatures++;
      }
    }

    // All signatures added. Finalize.
    if (signatures >= m) {
      // Remove empty slots left over.
      for (i = len - 1; i >= 1; i--) {
        if (Array.isArray(input.script[i]) && !input.script[i].length) {
          input.script.splice(i, 1);
          len--;
        }
      }

      // Remove signatures which are not required.
      // This should never happen except when dealing
      // with implementations that potentially handle
      // signature slots differently.
      while (signatures > m) {
        input.script.splice(len - 1, 1);
        signatures--;
        len--;
      }

      // Sanity checks.
      assert.equal(signatures, m);
      assert.equal(len - 1, m);
    }

    return signatures === m;
  }

  return false;
};

TX.prototype.scriptSig = function scriptSig(index, key, pub, redeem, type) {
  var input;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // Build script for input
  this.scriptInput(index, pub, redeem);

  // Sign input
  this.signInput(index, key, type);

  return input.script;
};

TX.prototype.output = function output(obj, value) {
  var options, output;

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

  output = bcoin.output({
    tx: this,
    value: options.value,
    script: options.script
  });

  this.outputs.push(output);

  this.scriptOutput(this.outputs.length - 1, options);

  return this;
};

TX.prototype.out = TX.prototype.output;

TX.prototype.scriptOutput = function scriptOutput(index, options) {
  var output, script, keys, m, n, hash, flags;

  if (typeof index !== 'number')
    index = this.outputs.indexOf(index);

  output = this.outputs[index];
  assert(output);

  if (!options)
    options = output;

  script = output.script;

  if (options instanceof bcoin.output) {
    options = Object.keys(options).reduce(function(out, key) {
      out[key] = options[key];
      return out;
    }, {});
  }

  if (options.addr) {
    options.address = options.addr;
    delete options.addr;
  }

  if (Array.isArray(options.address)) {
    options.keys = options.address.map(function(address) {
      return bcoin.wallet.addr2hash(address, 'pubkeyhash');
    });
    delete options.address;
  }

  if (options.minSignatures) {
    options.m = options.minSignatures;
    delete options.minSignatures;
  }

  if (options.color) {
    options.flags = options.color;
    delete options.color;
  }

  if (Array.isArray(options.keys)) {
    // Bare Multisig Transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // m [key1] [key2] ... n checkmultisig
    keys = options.keys.map(utils.toBuffer);

    m = options.m || keys.length;
    n = options.n || keys.length;

    if (!(m >= 1 && m <= n))
      return;

    if (!(n >= 1 && n <= (options.scripthash ? 15 : 3)))
      return;

    script = bcoin.script.redeem(keys, m, n);
  } else if (bcoin.wallet.validateAddress(options.address, 'scripthash')) {
    // P2SH Transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    // hash160 [20-byte-redeemscript-hash] equal
    script = [
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'scripthash'),
      'eq'
    ];
  } else if (options.address) {
    // P2PKH Transaction
    // dup hash160 [pubkey-hash] equalverify checksig
    script = [
      'dup',
      'hash160',
      bcoin.wallet.addr2hash(options.address, 'pubkeyhash'),
      'eqverify',
      'checksig'
    ];
  } else if (options.key) {
    // P2PK Transaction
    // [pubkey] checksig
    script = [
      utils.toBuffer(options.key),
      'checksig'
    ];
  } else if (options.flags) {
    // Nulldata Transaction
    // ret [data]
    flags = options.flags;
    if (typeof flags === 'string')
      flags = utils.ascii2array(flags);
    assert(utils.isBuffer(flags));
    assert(flags.length <= constants.script.maxOpReturn);
    script = [
      'ret',
      flags
    ];
  }

  // P2SH Transaction
  // hash160 [hash] eq
  if (options.scripthash) {
    if (options.lock != null) {
      script = [
        new bn(options.lock).toArray(),
        'checklocktimeverify',
        'drop'
      ].concat(script);
    }
    hash = utils.ripesha(bcoin.script.encode(script));
    script = [
      'hash160',
      hash,
      'eq'
    ];
  }

  output.script = script;
};

TX.prototype.getSubscript = function getSubscript(index) {
  var script = this.outputs[index].script;
  return bcoin.script.subscript(script);
};

TX.prototype.signatureHash = function signatureHash(index, s, type) {
  var copy = this.clone();
  var msg, hash;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type];

  assert(type != null);

  // bitcoind used to return 1 as an error code:
  // it ended up being treated like a hash.
  if (index >= copy.inputs.length)
    return constants.oneHash.slice();

  copy.inputs.forEach(function(input, i) {
    input.script = i === index ? s : [];
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
        output.value = new bn('ffffffffffffffff', 'hex');
      }
    });

    copy.inputs.forEach(function(input, i) {
      if (i !== index)
        input.seq = 0;
    });
  } else {
    assert(false);
  }

  if (type & constants.hashType.anyonecanpay) {
    copy.inputs.length = 1;
    copy.inputs[0].script = s;
  }

  msg = copy.render(true);

  utils.writeU32(msg, type, msg.length);

  hash = utils.dsha256(msg);

  return hash;
};

TX.prototype.verify = function verify(index, force, flags) {
  // Valid if included in block
  if (!force && this.ts !== 0)
    return true;

  if (this.inputs.length === 0)
    return false;

  return this.inputs.every(function(input, i) {
    var output;

    if (index != null && index !== i)
      return true;

    if (!input.out.tx)
      return false;

    output = input.out.tx.outputs[input.out.index];

    assert(input.out.tx.outputs.length > input.out.index);
    assert.equal(input.out.tx.hash('hex'), input.out.hash);

    // Transaction cannot reference itself
    if (input.out.tx.hash('hex') === this.hash('hex'))
      return false;

    return bcoin.script.verify(input.script, output.script, this, i, flags);
  }, this);
};

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && +this.inputs[0].out.hash === 0;
};

TX.prototype.maxSize = function maxSize() {
  var copy = this.clone();
  var i, input, total, size, s, m, n;

  // Create copy with 0-script inputs
  for (i = 0; i < copy.inputs.length; i++)
    copy.inputs[i].script = [];

  total = copy.render().length;

  // Add size for signatures and public keys
  for (i = 0; i < copy.inputs.length; i++) {
    input = copy.inputs[i];
    size = 0;

    // Get the previous output's subscript
    s = input.out.tx.getSubscript(input.out.index);

    if (bcoin.script.isPubkey(s)) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (bcoin.script.isPubkeyhash(s)) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 65;
    } else if (bcoin.script.isMultisig(s)) {
      // Bare Multisig
      // Get the previous m value:
      m = s[0];
      if (Array.isArray(m))
        m = m[0];
      assert(m >= 1 && m <= 3);
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
    } else if (bcoin.script.isScripthash(s)) {
      // P2SH Multisig
      // This technically won't work well for other
      // kinds of P2SH. It will also over-estimate
      // the fee by a lot (at least 10000 satoshis
      // since we don't have access to the m and n
      // values), which will be recalculated later.
      // If fee turns out to be smaller later, we
      // simply add more of the fee to the change
      // output.
      // m value
      m = 15;
      // n value
      n = 15;
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
      // OP_PUSHDATA2 [redeem]
      size += 3;
      // m value
      size += 1;
      // OP_PUSHDATA0 [key] ...
      size += (1 + 65) * n;
      // n value
      size += 1;
      // OP_CHECKMULTISIG
      size += 1;
    }

    // Byte for varint size of input script
    if (size < 0xfd)
      size += 0;
    else if (size <= 0xffff)
      size += 2;
    else if (size <= 0xffffffff)
      size += 4;
    else
      size += 8;

    total += size;
  }

  return total;
};

TX.prototype.getUnspent = function getUnspent(unspent) {
  var tx = this.clone();
  var cost = tx.funds('out');
  var fee = 1;
  var total = cost.addn(constants.tx.fee);
  var inputs = [];
  var lastAdded = 0;
  var size, addFee, change;

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
  tx.output({
    script: [],
    value: new bn(0)
  });

  // Change fee value if it is more than 1024 bytes
  // (10000 satoshi for every 1024 bytes)
  do {
    // Calculate maximum possible size after signing
    size = tx.maxSize();

    addFee = Math.ceil(size / 1024) - fee;
    total.iaddn(addFee * constants.tx.fee);
    fee += addFee;

    // Failed to get enough funds, add more inputs
    if (tx.funds('in').cmp(total) < 0)
      unspent.slice(lastAdded).every(addInput);
  } while (tx.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

  // Expose `total`
  this.total = total;

  // Still failing to get enough funds
  if (tx.funds('in').cmp(total) < 0)
    return null;

  // How much money is left after sending outputs
  change = tx.funds('in').sub(total);

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
    || result.inputs[0].output.address;

  result.inputs.forEach(function(input) {
    this.input(input);
  }, this);

  if (result.change.cmpn(constants.tx.dust) < 0) {
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
  var size, real, fee;

  if (!output) {
    this.output({
      address: this.changeAddress,
      value: new bn(0)
    });
    output = this.outputs[this.outputs.length - 1];
  }

  size = this.render().length;
  real = Math.ceil(size / 1024) * constants.tx.fee;
  fee = this.getFee().toNumber();

  if (real === fee) {
    if (!this.changeOutput)
      this.outputs.pop();
    return;
  }

  if (real > fee) {
    if (output.value.cmpn(real - fee) < 0) {
      this.outputs.pop();
      this.changeOutput = null;
      return;
    }
    output.value.isubn(real - fee);
  } else {
    output.value.iaddn(fee - real);
  }

  if (output.value.cmpn(constants.tx.dust) < 0) {
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

TX.prototype.fill = function fill(txs) {
  var inputs;

  if (txs instanceof bcoin.txPool)
    txs = txs._all;
  else if (txs instanceof bcoin.wallet)
    txs = txs.tx._all;

  if (Array.isArray(txs)) {
    txs = txs.reduce(function(out, tx) {
      out[tx.hash('hex')] = tx;
      return out;
    }, {});
  }

  inputs = this.inputs.filter(function(input) {
    if (!input.out.tx && txs[input.out.hash])
      input.out.tx = txs[input.out.hash];
    return !!input.out.tx;
  }, this);

  return inputs.length === this.inputs.length;
};

// Used for postVerify/ContextualBlockCheck and miner isFinalTx call.
// BIP113 will require that time-locked transactions have nLockTime set to
// less than the median time of the previous block they're contained in.
TX.prototype.isFinalBlock = function isFinalBlock(block, prev, useMedian) {
  var height = prev.height + 1;
  var ts = useMedian ? prev.getMedianTime() : block.ts;
  return this.isFinal(height, ts);
};

// Used in AcceptToMemoryPool
TX.prototype.isFinalMempool = function isFinalMempool(useMedian) {
  var height = this.chain.height() + 1;
  var ts = useMedian
    ? this.chain.getTip().getMedianTime()
    : utils.now();
  return this.isFinal(height, ts);
};

// Used in the original bitcoind code for AcceptBlock
TX.prototype.isFinalLegacy = function isFinalLegacy(block) {
  var ts = block ? block.ts : utils.now();
  var height = this.chain.height();
  return this.isFinal(height, ts);
};

TX.prototype.isFinal = function isFinal(height, ts) {
  var threshold = constants.locktimeThreshold;
  var i;

  if (!this.chain)
    return true;

  if (this.lock === 0)
    return true;

  if (this.lock < (this.lock < threshold ? height : ts))
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].seq !== 0xffffffff)
      return false;
  }

  return true;
};

TX.prototype.sigops = function sigops(scripthash, accurate) {
  var n = 0;
  this.inputs.forEach(function(input) {
    n += bcoin.script.sigops(input.script, accurate);
    if (scripthash && !this.isCoinbase())
      n += bcoin.script.sigopsScripthash(input.script);
  }, this);
  this.outputs.forEach(function(output) {
    n += bcoin.script.sigops(output.script, accurate);
  }, this);
  return n;
};

TX.prototype.isStandard = function isStandard() {
  var i, input, output, type;
  var nulldata = 0;

  if (this.version > constants.tx.version || this.version < 1)
    return false;

  if (this.size() > constants.tx.maxSize)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (script.size(input.script) > 1650)
      return false;

    if (!bcoin.script.pushOnly(input.script))
      return false;
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    type = bcoin.script.standard(output.script);

    if (!bcoin.script.isStandard(output.script))
      return false;

    if (!type)
      return false;

    if (type === 'nulldata') {
      nulldata++;
      continue;
    }

    if (type === 'multisig' && !constants.tx.bareMultisig)
      return false;

    if (output.value.cmpn(constants.tx.dust) < 0)
      return false;
  }

  if (nulldata > 1)
    return false;

  return true;
};

TX.prototype.isStandardInputs = function isStandardInputs(flags) {
  var i, input, prev, args, stack, res, s, targs;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.out.tx)
      return false;

    prev = input.out.tx[input.out.index];

    if (!prev)
      return false;

    args = bcoin.script.args(prev.script);

    if (args < 0)
      return false;

    stack = [];

    res = bcoin.script.execute(input.script, stack, this, i, flags);

    if (!res)
      return false;

    if (bcoin.script.isScripthash(prev.script)) {
      if (stack.length === 0)
        return false;

      s = stack[stack.length - 1];

      if (!Array.isArray(s))
        return false;

      s = bcoin.script.decode(s);

      if (bcoin.script.standard(s)) {
        targs = bcoin.script.args(s);
        if (targs < 0)
          return false;
        args += targs;
      } else {
        return script.sigops(s, true) <= constants.script.maxScripthashSigops;
      }
    }

    if (stack.length !== args)
      return false;
  }

  return true;
};

TX.prototype.getHeight = function getHeight() {
  if (!this.chain)
    return -1;
  return this.block ? this.chain.getHeight(this.block) : -1;
};

TX.prototype.getConfirmations = function getConfirmations() {
  var top, height;

  if (!this.chain)
    return 0;

  top = this.chain.height();
  height = this.getHeight();

  if (height === -1)
    return 0;

  return top - height + 1;
};

TX.prototype.__defineGetter__('chain', function() {
  return this._chain || bcoin.chain.global;
});

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

TX.prototype.__defineGetter__('height', function() {
  return this.getHeight();
});

TX.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations();
});

TX.prototype.inspect = function inspect() {
  var copy = bcoin.tx(this);
  copy.__proto__ = null;
  if (this.block)
    copy.block = this.block;
  delete copy._raw;
  delete copy._chain;
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
    changeIndex: this.outputs.indexOf(this.changeOutput),
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

  data._raw = raw;
  data._size = raw.length;

  tx = new TX(data);
  tx.ts = json.ts;
  tx.block = json.block || null;
  tx.ps = json.ps;

  if (data.changeIndex >= 0) {
    tx.changeOutput = tx.outputs[data.changeIndex];
    assert(tx.changeOutput);
  }

  return tx;
};

/**
 * Expose
 */

module.exports = TX;

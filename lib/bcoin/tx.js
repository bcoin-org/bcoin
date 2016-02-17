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

  if (!data)
    data = {};

  this.type = 'tx';
  this.version = data.version || 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = data.locktime || 0;
  this.ts = data.ts || 0;
  this.block = data.block || null;
  this._hash = null;

  // Legacy
  if (data.lock != null)
    this.locktime = data.lock;

  this._raw = data._raw || null;
  this._size = data._size || 0;
  this._offset = data._offset || 0;

  this.height = data.height != null ? data.height : -1;
  this.network = data.network || false;
  this.relayedBy = data.relayedBy || '0.0.0.0';

  this._chain = data.chain;

  if (data.inputs) {
    assert(this.inputs.length === 0);
    data.inputs.forEach(function(input) {
      this.addInput(input);
    }, this);
  }

  if (data.outputs) {
    assert(this.outputs.length === 0);
    data.outputs.forEach(function(output) {
      this.addOutput(output);
    }, this);
  }

  if (block && !data.ts) {
    this.network = true;
    this.relayedBy = block.relayedBy;
    if (block.subtype === 'merkleblock') {
      if (block.hasTX(this.hash('hex'))) {
        this.ts = block.ts;
        this.block = block.hash('hex');
        this.height = block.height;
      }
    } else {
      this.ts = block.ts;
      this.block = block.hash('hex');
      this.height = block.height;
    }
  }

  this.changeIndex = data.changeIndex != null ? data.changeIndex : -1;

  // ps = Pending Since
  this.ps = this.ts === 0 ? utils.now() : 0;
}

// Legacy
TX.prototype.__defineSetter__('lock', function(locktime) {
  return this.locktime = locktime;
});

TX.prototype.__defineGetter__('lock', function() {
  return this.locktime;
});

TX.prototype.__defineSetter__('lockTime', function(locktime) {
  return this.locktime = locktime;
});

TX.prototype.__defineGetter__('lockTime', function() {
  return this.locktime;
});

TX.prototype.clone = function clone() {
  return new TX(this);
};

TX.prototype.isStatic = function isStatic() {
  return this.ts !== 0 || this.network;
};

TX.prototype.hash = function hash(enc, force) {
  var hash;

  if (!force && this._hash)
    return enc === 'hex' ? utils.toHex(this._hash) : this._hash;

  if (!force && this.isStatic() && this._raw)
    hash = utils.dsha256(this._raw);
  else
    hash = utils.dsha256(this.render(true));

  if (this.isStatic())
    this._hash = hash;

  return enc === 'hex' ? utils.toHex(hash) : hash;
};

TX.prototype.render = function render(force) {
  if (!force && this.isStatic() && this._raw)
    return utils.toArray(this._raw);
  return bcoin.protocol.framer.tx(this);
};

TX.prototype.getSize = function getSize() {
  return this._size || this.render().length;
};

TX.prototype.size = TX.prototype.getSize;

TX.prototype.addInput = function addInput(i, index) {
  this._addInput(i, index);
  return this;
};

TX.prototype.input = TX.prototype.addInput;

// tx._addInput(tx, index)
// tx._addInput(hash, index)
// tx._addInput(input)
// tx._addInput({ hash: hash, index: index })
// tx._addInput({ tx: tx, index: index })
TX.prototype._addInput = function _addInput(options, index) {
  var coin, input, ex, i, prevout, isInput;

  if (options instanceof TX) {
    options = { tx: options, index: index };
  } else if (typeof options === 'string' || utils.isBuffer(options)) {
    options = { hash: options, index: index };
  }

  if (options.out)
    options.prevout = options.out;

  if (options.seq != null)
    options.sequence = options.seq;

  if (!options.prevout) {
    if (options instanceof bcoin.coin) {
      options = {
        prevout: { hash: options.hash, index: options.index },
        output: options
      };
    } else if (options.tx) {
      coin = bcoin.coin(options.tx, options.index);
      options = {
        prevout: { hash: options.tx.hash('hex'), index: options.index },
        output: coin,
        script: options.script,
        sequence: options.sequence
      };
    } else if (options.hash) {
      options = {
        prevout: { hash: options.hash, index: options.index },
        output: options.output,
        script: options.script,
        sequence: options.sequence
      };
    }
  } else {
    isInput = true;
  }

  input = bcoin.input({
    tx: this,
    prevout: {
      hash: options.prevout.hash,
      index: options.prevout.index
    },
    output: options.output,
    script: options.script,
    sequence: options.sequence,
    _size: isInput ? options._size : null,
    _offset: isInput ? options._offset : null
  });

  // Try modifying existing input first
  i = this._inputIndex(input.prevout.hash, input.prevout.index);
  if (i !== -1) {
    ex = this.inputs[i];
    input.output = input.output || ex.output;
    input.sequence = input.sequence != null ? input.sequence : ex.sequence;
    input.script = input.script.length ? input.script : ex.script;
    this.inputs[i] = input;
  } else {
    this.inputs.push(input);
    i = this.inputs.length - 1;
  }

  return i;
};

TX.prototype._input = TX.prototype._addInput;

TX.prototype._inputIndex = function _inputIndex(hash, index) {
  var i, ex;

  if (hash instanceof TX)
    hash = hash.hash('hex');

  for (i = 0; i < this.inputs.length; i++) {
    ex = this.inputs[i];
    if (ex.prevout.hash === hash && ex.prevout.index === index)
      return i;
  }

  return -1;
};

TX.prototype.scriptInput = function scriptInput(index, publicKey, redeem) {
  var input, s, n, i;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // Already has a script template (at least)
  // if (input.script.length)
  //   return;

  // We should have previous outputs by now.
  assert(input.output);

  // Get the previous output's subscript
  s = input.output.script;

  // P2SH
  if (bcoin.script.isScripthash(s)) {
    if (!redeem)
      return false;
    s = bcoin.script.decode(redeem);
  } else {
    redeem = null;
  }

  if (bcoin.script.isPubkey(s)) {
    // P2PK
    if (!utils.isEqual(s[0], publicKey))
      return false;
    // Already has a script template (at least)
    if (input.script.length)
      return true;
    input.script = [[]];
  } else if (bcoin.script.isPubkeyhash(s)) {
    // P2PKH
    if (!utils.isEqual(s[2], bcoin.address.hash160(publicKey)))
      return false;
    // Already has a script template (at least)
    if (input.script.length)
      return true;
    input.script = [[], publicKey];
  } else if (bcoin.script.isMultisig(s)) {
    // Multisig
    for (i = 0; i < s.length; i++) {
      if (utils.isEqual(s[i], publicKey))
        break;
    }

    if (i === s.length)
      return false;

    // Already has a script template (at least)
    if (input.script.length)
      return true;

    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    input.script = [[]];

    // Grab `n` value (number of keys).
    n = s[s.length - 2];

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      input.script[i + 1] = [];
  } else {
    for (i = 0; i < s.length; i++) {
      if (utils.isEqual(s[i], publicKey))
        break;
    }

    if (i === s.length)
      return false;

    // Already has a script template (at least)
    if (input.script.length)
      return true;

    // Likely a non-standard scripthash multisig
    // input. Determine n value by counting keys.
    // Also, only allow nonstandard types for
    // scripthash.
    if (redeem) {
      input.script = [[]];
      // Fill script with `n` signature slots.
      for (i = 0; i < s.length; i++) {
        if (bcoin.script.isKey(s[i]))
          input.script.push([]);
      }
    }
  }

  // P2SH requires the redeem script after signatures
  if (redeem)
    input.script.push(redeem);

  return true;
};

TX.prototype.createSignature = function createSignature(index, key, type) {
  var input, s, hash, signature;

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
  assert(input.output);

  // Get the previous output's subscript
  s = input.output.script;

  // We need to grab the redeem script when
  // signing p2sh transactions.
  if (bcoin.script.isScripthash(s))
    s = bcoin.script.getRedeem(input.script);

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, s, type);

  // Sign the transaction with our one input
  signature = bcoin.script.sign(hash, key, type);

  // Something is broken if this doesn't work:
  assert(bcoin.script.checksig(hash, signature, key));

  return signature;
};

// Legacy
TX.prototype.signature = TX.prototype.createSignature;

// Sign the now-built scriptSigs
TX.prototype.signInput = function signInput(index, key, type) {
  var input, s, signature, ki, signatures, i;
  var len, m, n, keys, publicKey, keyHash;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.output);

  // Create our signature.
  signature = this.createSignature(index, key, type);

  // Get the previous output's subscript
  s = input.output.script;

  // Script length, needed for multisig
  len = input.script.length;

  // We need to grab the redeem script when
  // signing p2sh transactions.
  if (bcoin.script.isScripthash(s)) {
    s = bcoin.script.getRedeem(input.script);
    // Decrement `len` to avoid the redeem script
    len--;
  }

  // Get pubkey.
  publicKey = key.getPublic(true, 'array');

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
    if (!utils.isEqual(publicKey, s[0]))
      return false;

    input.script[0] = signature;

    return true;
  }

  if (bcoin.script.isPubkeyhash(s)) {
    // P2PKH

    // Something is wrong. Abort.
    if (!Array.isArray(input.script[0]))
      return false;

    // Already signed.
    if (input.script[0].length)
      return true;

    // Make sure the pubkey hash is ours.
    keyHash = bcoin.address.hash160(publicKey);
    if (!utils.isEqual(keyHash, s[2]))
      return false;

    input.script[0] = signature;

    return true;
  }

  if (bcoin.script.isMultisig(s)) {
    // Multisig

    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = s.slice(1, -2);

    // Grab `m` value (number of sigs required).
    m = s[0];

    // Grab `n` value (number of keys).
    n = s[s.length - 2];
  } else {
    // Only allow non-standard signing for
    // scripthash.
    if (len !== input.script.length - 1)
      return false;

    keys = [];

    for (i = 0; i < s.length; i++) {
      if (bcoin.script.isKey(s[i]))
        keys.push(s[i]);
    }

    n = keys.length;
    m = n;
  }

  // Something is very wrong here. Abort.
  if (len - 1 > n)
    return false;

  // Count the number of current signatures.
  signatures = 0;
  for (i = 1; i < len; i++) {
    if (bcoin.script.isSignature(input.script[i]))
      signatures++;
  }

  // Signatures are already finalized.
  if (signatures === m && len - 1 === m)
    return true;

  // This can happen in a case where another
  // implementation adds signatures willy-nilly
  // or by `m`. Add some signature slots for
  // us to use.
  while (len - 1 < n) {
    input.script.splice(len, 0, []);
    len++;
  }

  // Find the key index so we can place
  // the signature in the same index.
  for (ki = 0; ki < keys.length; ki++) {
    if (utils.isEqual(publicKey, keys[ki]))
      break;
  }

  // Our public key is not in the prev_out
  // script. We tried to sign a transaction
  // that is not redeemable by us.
  if (ki === keys.length)
    return false;

  // Offset key index by one to turn it into
  // "sig index". Accounts for OP_0 byte at
  // the start.
  ki++;

  // Add our signature to the correct slot
  // and increment the total number of
  // signatures.
  if (ki < len && signatures < m) {
    if (bcoin.script.isDummy(input.script[ki])) {
      input.script[ki] = signature;
      signatures++;
    }
  }

  // All signatures added. Finalize.
  if (signatures >= m) {
    // Remove empty slots left over.
    for (i = len - 1; i >= 1; i--) {
      if (bcoin.script.isDummy(input.script[i])) {
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
};

TX.prototype.sign = function sign(index, key, redeem, type) {
  var publicKey = key.getPublic(true, 'array');
  var input;

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  input = this.inputs[index];
  assert(input);

  // Build script for input
  if (!this.scriptInput(index, publicKey, redeem))
    return false;

  // Sign input
  if (!this.signInput(index, key, type))
    return false;

  return true;
};

TX.prototype.isSigned = function isSigned(index, required) {
  var i, input, s, len, m, j, total;

  if (this._signed)
    return true;

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  if (index != null)
    assert(this.inputs[index]);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (index != null && i !== index)
      continue;

    // We can't check for signatures unless
    // we have the previous output.
    assert(input.output);

    // Get the prevout's subscript
    s = input.output.script;

    // Script length, needed for multisig
    len = input.script.length;

    // Grab the redeem script if P2SH
    if (bcoin.script.isScripthash(s)) {
      s = bcoin.script.getRedeem(input.script);
      // Decrement `len` to avoid the redeem script
      len--;
    }

    // Check for signatures.
    // P2PK
    if (bcoin.script.isPubkey(s)) {
      if (!bcoin.script.isSignature(input.script[0]))
        return false;
      continue;
    }

    // P2PK
    if (bcoin.script.isPubkeyhash(s)) {
      if (!bcoin.script.isSignature(input.script[0]))
        return false;
      continue;
    }

    // Multisig
    if (bcoin.script.isMultisig(s)) {
      // Grab `m` value (number of required sigs).
      m = s[0];
      if (Array.isArray(m))
        m = m[0] || 0;

      // Ensure all members are signatures.
      for (j = 1; j < len; j++) {
        if (!bcoin.script.isSignature(input.script[j]))
          return false;
      }

      // Ensure we have the correct number
      // of required signatures.
      if (len - 1 !== m)
        return false;

      continue;
    }

    if (required == null)
      continue;

    // Unknown
    total = 0;
    for (j = 0; j < input.script.length; j++) {
      if (bcoin.script.isSignatureEncoding(input.script[j]))
        total++;
    }

    if (total !== required)
      return false;
  }

  return this._signed = true;
};

TX.prototype.addOutput = function addOutput(obj, value) {
  var options, output;

  if ((obj instanceof bcoin.wallet) || (obj instanceof bcoin.address))
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
    value: options.value,
    script: options.script,
    _size: options._size,
    _offset: options._offset
  });

  this.outputs.push(output);

  this.scriptOutput(this.outputs.length - 1, options);

  return this;
};

TX.prototype.out = TX.prototype.addOutput;
TX.prototype.output = TX.prototype.addOutput;

TX.prototype.scriptOutput = function scriptOutput(index, options) {
  var output, script, keys, m, n, hash, flags;

  if (options instanceof bcoin.output)
    return;

  if (typeof index !== 'number')
    index = this.outputs.indexOf(index);

  output = this.outputs[index];
  assert(output);

  script = output.script;

  if (options.keys) {
    // Bare Multisig Transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // m [key1] [key2] ... n checkmultisig
    keys = options.keys.map(utils.toBuffer);

    m = options.m;
    n = options.n || keys.length;

    if (!(m >= 1 && m <= n))
      return;

    if (!(n >= 1 && n <= (options.scriptHash ? 15 : 3)))
      return;

    script = bcoin.script.createMultisig(keys, m, n);
  } else if (bcoin.address.getType(options.address) === 'scripthash') {
    // P2SH Transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    // hash160 [20-byte-redeemscript-hash] equal
    script = bcoin.script.createScripthash(
      bcoin.address.toHash(options.address, 'scripthash')
    );
  } else if (options.address) {
    // P2PKH Transaction
    // dup hash160 [pubkey-hash] equalverify checksig
    script = bcoin.script.createPubkeyhash(
      bcoin.address.toHash(options.address, 'pubkeyhash')
    );
  } else if (options.key) {
    // P2PK Transaction
    // [pubkey] checksig
    script = [
      utils.toBuffer(options.key),
      'checksig'
    ];
  } else if (options.flags) {
    // Nulldata Transaction
    // return [data]
    flags = options.flags;
    if (typeof flags === 'string')
      flags = utils.ascii2array(flags);
    assert(utils.isBuffer(flags));
    assert(flags.length <= constants.script.maxOpReturn);
    script = bcoin.script.createNulldata(flags);
  }

  // P2SH Transaction
  // hash160 [hash] eq
  if (options.scriptHash) {
    if (options.locktime != null) {
      script = [
        bcoin.script.array(options.locktime),
        'checklocktimeverify',
        'drop'
      ].concat(script);
    }
    hash = utils.ripesha(bcoin.script.encode(script));
    script = bcoin.script.createScripthash(hash);
  }

  output.script = script;
};

TX.prototype.getSubscript = function getSubscript(index) {
  var script;

  if (typeof index !== 'number')
    index = this.outputs.indexOf(index);

  assert(this.outputs[index]);

  script = this.outputs[index].script;

  return bcoin.script.getSubscript(script);
};

TX.prototype.signatureHash = function signatureHash(index, s, type) {
  var copy = this.clone();
  var i, msg, hash;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type];

  assert(index >= 0 && index < copy.inputs.length)
  assert(Array.isArray(s));

  // Disable this for now. We allow null hash types
  // because bitcoind allows empty signatures. On
  // another note, we allow all weird sighash types
  // if strictenc is not enabled.
  // assert(utils.isFinite(type));

  // Remove all signatures.
  for (i = 0; i < copy.inputs.length; i++)
    copy.inputs[i].script = [];

  // Set our input to previous output's script
  copy.inputs[index].script = s;

  if ((type & 0x1f) === constants.hashType.none) {
    // Drop all outputs. We don't want to sign them.
    copy.outputs = [];

    // Allow input sequence updates for other inputs.
    for (i = 0; i < copy.inputs.length; i++) {
      if (i !== index)
        copy.inputs[i].sequence = 0;
    }
  } else if ((type & 0x1f) === constants.hashType.single) {
    // Bitcoind used to return 1 as an error code:
    // it ended up being treated like a hash.
    if (index >= copy.outputs.length)
      return constants.oneHash.slice();

    // Drop all the outputs after the input index.
    copy.outputs.length = index + 1;

    // Null outputs that are not the at current input index.
    for (i = 0; i < copy.outputs.length; i++) {
      if (i !== index) {
        copy.outputs[i].script = [];
        copy.outputs[i].value = new bn('ffffffffffffffff', 'hex');
      }
    }

    // Allow input sequence updates for other inputs.
    for (i = 0; i < copy.inputs.length; i++) {
      if (i !== index)
        copy.inputs[i].sequence = 0;
    }
  }

  // Only sign our input. Allows anyone to add inputs.
  if (type & constants.hashType.anyonecanpay) {
    copy.inputs[0] = copy.inputs[index];
    copy.inputs.length = 1;
  }

  msg = copy.render(true);

  utils.writeU32(msg, type, msg.length);

  hash = utils.dsha256(msg);

  return hash;
};

TX.prototype.tbsHash = function tbsHash(enc, force) {
  var copy = this.clone();
  var i;

  if (this.isCoinbase())
    return this.hash(enc);

  if (!this._tbsHash || force) {
    for (i = 0; i < copy.inputs.length; i++) {
      if (!copy.inputs[i].isCoinbase())
        copy.inputs[i].script = [];
    }

    this._tbsHash = utils.dsha256(copy.render(true));
  }

  return enc === 'hex'
    ? utils.toHex(this._tbsHash)
    : this._tbsHash.slice();
};

TX.prototype.verify = function verify(index, force, flags) {
  // Valid if included in block
  if (!force && this.ts !== 0)
    return true;

  if (this.inputs.length === 0)
    return false;

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  if (index != null)
    assert(this.inputs[index]);

  if (this.isCoinbase())
    return true;

  return this.inputs.every(function(input, i) {
    if (index != null && i !== index)
      return true;

    if (!input.output) {
      utils.debug('Warning: Not all outputs available for tx.verify().');
      return false;
    }

    return bcoin.script.verify(input.script, input.output.script, this, i, flags);
  }, this);
};

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && +this.inputs[0].prevout.hash === 0;
};

TX.prototype.maxSize = function maxSize(maxM, maxN) {
  var copy = this.clone();
  var i, j, input, total, size, s, m, n;

  // Create copy with 0-script inputs
  for (i = 0; i < copy.inputs.length; i++)
    copy.inputs[i].script = [];

  total = copy.render().length;

  // Add size for signatures and public keys
  for (i = 0; i < copy.inputs.length; i++) {
    input = copy.inputs[i];
    size = 0;

    assert(input.output);

    // Get the previous output's subscript
    s = input.output.script;

    // If we have access to the redeem script,
    // we can use it to calculate size much easier.
    if (this.inputs[i].script.length && bcoin.script.isScripthash(s)) {
      s = bcoin.script.getRedeem(this.inputs[i].script);
      // Need to add the redeem script size
      // here since it will be ignored by
      // the isMultisig clause.
      // OP_PUSHDATA2 [redeem]
      size += 3 + bcoin.script.getSize(s);
    }

    if (bcoin.script.isPubkey(s)) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (bcoin.script.isPubkeyhash(s)) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
    } else if (bcoin.script.isMultisig(s)) {
      // Bare Multisig
      // Get the previous m value:
      m = s[0];
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
      m = maxM || 15;
      // n value
      n = maxN || 15;
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
      // OP_PUSHDATA2 [redeem]
      size += 3;
      // m value
      size += 1;
      // OP_PUSHDATA0 [key] ...
      size += (1 + 33) * n;
      // n value
      size += 1;
      // OP_CHECKMULTISIG
      size += 1;
    } else {
      // OP_PUSHDATA0 [signature]
      for (j = 0; j < s.length; j++) {
        if (bcoin.script.isKey(s[j]))
          size += 1 + 73;
      }
    }

    // Byte for varint size of input script
    size += utils.sizeIntv(size);

    total += size;
  }

  return total;
};

TX.prototype.getInputs = function getInputs(unspent, options) {
  var self = this;
  var tx = this.clone();
  var outputValue = tx.getOutputValue();
  var totalkb = 1;
  var inputs = [];
  var lastAdded = 0;
  var minFee = constants.tx.minFee;
  var dustThreshold = constants.tx.dustThreshold;
  var i, size, newkb, change;
  var fee;

  if (!options || typeof options !== 'object') {
    options = {
      changeAddress: arguments[1],
      fee: arguments[2]
    };
  }

  if (!options.selection || options.selection === 'age') {
    // Oldest unspents first
    unspent = unspent.slice().sort(function(a, b) {
      return a.height - b.height;
    });
  } else if (options.selection === 'random' || options.selection === 'all') {
    // Random unspents
    unspent = unspent.slice().sort(function(a, b) {
      return Math.random() > 0.5 ? 1 : -1;
    });
  }

  function total() {
    if (options.subtractFee)
      return outputValue;
    return outputValue.add(fee);
  }

  function isFull() {
    return tx.getInputValue().cmp(total()) >= 0;
  }

  function addCoins() {
    var i, index;

    for (i = lastAdded; i < unspent.length; i++) {
      // Add new inputs until TX will have enough
      // funds to cover both minimum post cost
      // and fee.
      index = tx._addInput(unspent[i]);
      inputs.push(new bcoin.input(tx.inputs[index]));
      lastAdded++;

      if (options.wallet)
        options.wallet.scriptInputs(tx, index);

      if (options.selection === 'all')
        continue;

      // Stop once we're full.
      if (isFull())
        break;
    }
  }

  if (options.fee) {
    fee = options.fee;

    // Transfer `total` funds maximum.
    addCoins();
  } else {
    fee = new bn(minFee);

    // Transfer `total` funds maximum.
    addCoins();

    // Add dummy output (for `change`) to
    // calculate maximum TX size.
    tx.addOutput({
      address: options.changeAddress,
      value: new bn(0)
    });

    // Change fee value if it is more than 1024
    // bytes (10000 satoshi for every 1024 bytes).
    do {
      // Calculate max possible size after signing.
      size = tx.maxSize(options.m, options.n);

      // if (newkb == null && tx.isFree(size)) {
      //   fee = new bn(0);
      //   break;
      // }

      newkb = Math.ceil(size / 1024) - totalkb;
      fee.iaddn(newkb * minFee);
      totalkb += newkb;

      // Failed to get enough funds, add more inputs.
      if (!isFull())
        addCoins();
    } while (!isFull() && lastAdded < unspent.length);
  }

  if (!isFull()) {
    // Still failing to get enough funds.
    inputs = null;
  } else {
    // How much money is left after filling outputs.
    change = tx.getInputValue().sub(total());

    // Attempt to subtract fee.
    if (options.subtractFee) {
      for (i = 0; i < tx.outputs.length; i++) {
        if (tx.outputs[i].value.cmp(fee.addn(dustThreshold)) >= 0) {
          tx.outputs[i].value.isub(fee);
          break;
        }
      }
      // Could not subtract fee
      if (i === tx.outputs.length)
        inputs = null;
    }
  }

  // Return necessary inputs and change.
  return {
    inputs: inputs,
    change: change,
    fee: fee,
    total: total(),
    kb: totalkb,
    unspent: unspent.slice(0, lastAdded)
  };
};

TX.prototype.fill = function fill(unspent, options) {
  var result;

  if (!options || typeof options !== 'object') {
    options = {
      changeAddress: arguments[1],
      fee: arguments[2]
    };
  }

  assert(unspent);
  assert(options.changeAddress);

  result = this.getInputs(unspent, options);

  this.requiredFunds = result.total;

  if (!result.inputs)
    return result;

  result.inputs.forEach(function(input) {
    this.addInput(input);
  }, this);

  if (result.change.cmpn(constants.tx.dustThreshold) < 0) {
    // Do nothing. Change is added to fee.
    assert.equal(
      this.getFee().toNumber(),
      result.fee.add(result.change).toNumber()
    );
    this.changeIndex = -1;
  } else {
    this.addOutput({
      address: options.changeAddress,
      value: result.change
    });

    this.changeIndex = this.outputs.length - 1;

    assert.equal(this.getFee().toNumber(), result.fee.toNumber());
  }

  return result;
};

// https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
TX.prototype.sortMembers = function sortMembers() {
  var changeOutput;

  if (this.changeIndex !== -1) {
    changeOutput = this.outputs[this.changeIndex];
    assert(changeOutput);
  }

  this.inputs = this.inputs.slice().sort(function(a, b) {
    var h1 = utils.toArray(a.prevout.hash, 'hex');
    var h2 = utils.toArray(b.prevout.hash, 'hex');

    var res = utils.cmp(h1, h2);
    if (res !== 0)
      return res;

    return a.prevout.index - b.prevout.index;
  });

  this.outputs = this.outputs.slice().sort(function(a, b) {
    var res = a.value.cmp(b.value);
    if (res !== 0)
      return res;

    a = bcoin.script.encode(a.script);
    b = bcoin.script.encode(b.script);

    return utils.cmp(a, b);
  });

  if (this.changeIndex !== -1) {
    this.changeIndex = this.outputs.indexOf(changeOutput);
    assert(this.changeIndex !== -1);
  }
};

// Legacy
TX.prototype.fillUnspent = TX.prototype.fill;
TX.prototype.fillInputs = TX.prototype.fill;

TX.prototype.getFee = function getFee() {
  if (!this.hasPrevout())
    return new bn(0);

  return this.getInputValue().sub(this.getOutputValue());
};

TX.prototype.getInputValue = function getInputValue() {
  var acc = new bn(0);

  if (this.inputs.length === 0)
    return acc;

  if (!this.hasPrevout())
    return acc;

  return this.inputs.reduce(function(acc, input) {
    return acc.iadd(input.output.value);
  }, acc);
};

TX.prototype.getOutputValue = function getOutputValue() {
  var acc = new bn(0);

  if (this.outputs.length === 0)
    return acc;

  return this.outputs.reduce(function(acc, output) {
    return acc.iadd(output.value);
  }, acc);
};

TX.prototype.getFunds = function getFunds(side) {
  var acc = new bn(0);

  if (side === 'in' || side === 'input')
    return this.getInputValue();

  return this.getOutputValue();
};

// Legacy
TX.prototype.funds = TX.prototype.getFunds;

TX.prototype.getTargetLocktime = function getTargetLocktime() {
  var bestValue = 0;
  var i, locktime, bestType;

  for (i = 0; i < this.inputs.length; i++) {
    locktime = this.inputs[i].getLocktime();

    if (!locktime)
      continue;

    // Incompatible types
    if (bestType && bestType !== locktime.type)
      return;

    bestType = locktime.type;

    if (locktime.value < bestValue)
      continue;

    bestValue = locktime.value;
  }

  return {
    type: bestType || 'height',
    value: bestValue
  };
};

TX.prototype.testInputs = function testInputs(addressTable, index, collect) {
  var inputs = [];
  var i, input;

  if (typeof addressTable === 'string')
    addressTable = [addressTable];

  if (Array.isArray(addressTable)) {
    addressTable = addressTable.reduce(function(out, address) {
      out[address] = true;
      return out;
    }, {});
  }

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  if (index != null)
    assert(this.inputs[index]);

  for (i = 0; i < this.inputs.length; i++) {
    if (index != null && i !== index)
      continue;

    input = this.inputs[i];

    if (input.test(addressTable)) {
      if (!collect)
        return true;
      inputs.push(input);
    }
  }

  if (!collect)
    return false;

  if (inputs.length === 0)
    return false;

  return inputs;
};

TX.prototype.testOutputs = function testOutputs(addressTable, index, collect) {
  var outputs = [];
  var i, output;

  if (typeof addressTable === 'string')
    addressTable = [addressTable];

  if (Array.isArray(addressTable)) {
    addressTable = addressTable.reduce(function(out, address) {
      out[address] = true;
      return out;
    }, {});
  }

  if (index && typeof index === 'object')
    index = this.outputs.indexOf(index);

  if (index != null)
    assert(this.outputs[index]);

  for (i = 0; i < this.outputs.length; i++) {
    if (index != null && i !== index)
      continue;

    output = this.outputs[i];

    if (output.test(addressTable)) {
      if (!collect)
        return true;
      outputs.push(output);
    }
  }

  if (!collect)
    return false;

  if (outputs.length === 0)
    return false;

  return outputs;
};

TX.prototype.avoidFeeSnipping = function avoidFeeSnipping(height) {
  if (height == null) {
    if (!this.chain)
      return;

    height = this.chain.height;
  }

  if (height === -1)
    height = 0;

  this.setLocktime(height);

  if ((Math.random() * 10 | 0) === 0)
    this.setLocktime(Math.max(0, this.locktime - (Math.random() * 100 | 0)));
};

TX.prototype.setLocktime = function setLocktime(locktime) {
  var i, input;

  this.locktime = locktime;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence === 0xffffffff)
      input.sequence = 0;
  }
};

TX.prototype.increaseFee = function increaseFee(unspent, address, fee) {
  var i, input, result;

  this.inputs = [];

  if (this.changeIndex !== -1)
    this.outputs.splice(this.changeIndex, 1);

  if (!fee)
    fee = this.getFee().add(new bn(10000));

  result = this.fill(unspent, address, fee);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.sequence = 0xffffffff - 1;
  }

  return !!result.inputs;
};

TX.prototype.hasPrevout = function hasPrevout() {
  if (this.inputs.length === 0)
    return false;

  return this.inputs.every(function(input) {
    return !!input.output;
  });
};

TX.prototype.fillPrevout = function fillPrevout(txs, unspent) {
  var inputs;

  if (txs instanceof bcoin.txPool) {
    unspent = txs._unspent;
    txs = txs._all;
  } else if (txs instanceof bcoin.wallet) {
    unspent = txs.tx._unspent;
    txs = txs.tx._all;
  }

  if (Array.isArray(txs)) {
    txs = txs.reduce(function(out, tx) {
      out[tx.hash('hex')] = tx;
      return out;
    }, {});
  }

  if (Array.isArray(unspent)) {
    unspent = unspent.reduce(function(out, coin) {
      out[coin.hash + '/' + coin.index] = coin;
      return out;
    }, {});
  }

  inputs = this.inputs.filter(function(input) {
    var key;

    if (!input.output) {
      key = input.prevout.hash + '/' + input.prevout.index;
      if (unspent && unspent[key])
        input.output = unspent[key];
      else if (txs && txs[input.prevout.hash])
        input.output = bcoin.coin(txs[input.prevout.hash], input.prevout.index);
    }

    return !!input.output;
  }, this);

  return inputs.length === this.inputs.length;
};

TX.prototype.isFinal = function isFinal(height, ts) {
  var threshold = constants.locktimeThreshold;
  var i;

  if (this.locktime === 0)
    return true;

  if (this.locktime < (this.locktime < threshold ? height : ts))
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].sequence !== 0xffffffff)
      return false;
  }

  return true;
};

TX.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var n = 0;
  this.inputs.forEach(function(input) {
    n += bcoin.script.getSigops(input.script, accurate);
    if (scriptHash && !this.isCoinbase())
      n += bcoin.script.getScripthashSigops(input.script);
  }, this);
  this.outputs.forEach(function(output) {
    n += bcoin.script.getSigops(output.script, accurate);
  }, this);
  return n;
};

TX.prototype.isStandard = function isStandard() {
  var i, input, output, type;
  var nulldata = 0;

  if (this.version > constants.tx.version || this.version < 1)
    return false;

  if (this.getSize() > constants.tx.maxSize)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (bcoin.script.getSize(input.script) > 1650)
      return false;

    // Not accurate?
    if (this.isCoinbase())
      continue;

    if (!bcoin.script.isPushOnly(input.script))
      return false;
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    type = bcoin.script.getType(output.script);

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

    if (output.value.cmpn(constants.tx.dustThreshold) < 0)
      return false;
  }

  if (nulldata > 1)
    return false;

  return true;
};

TX.prototype.isStandardInputs = function isStandardInputs(flags) {
  var i, input, args, stack, res, s, targs;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.output)
      return false;

    args = bcoin.script.getArgs(input.output.script);

    if (args < 0)
      return false;

    stack = [];

    res = bcoin.script.execute(input.script, stack, this, i, flags);

    if (!res)
      return false;

    if (bcoin.script.isScripthash(input.output.script)) {
      if (stack.length === 0)
        return false;

      s = stack[stack.length - 1];

      if (!Array.isArray(s))
        return false;

      s = bcoin.script.decode(s);

      if (bcoin.script.getType(s) !== 'unknown') {
        targs = bcoin.script.getArgs(s);
        if (targs < 0)
          return false;
        args += targs;
      } else {
        return script.getSigops(s, true) <= constants.script.maxScripthashSigops;
      }
    }

    if (stack.length !== args)
      return false;
  }

  return true;
};

TX.prototype.getPriority = function getPriority(size) {
  var sum, i, input, age, height;

  height = this.height;

  if (height === -1)
    height = null;

  if (!this.hasPrevout())
    return new bn(0);

  size = size || this.maxSize();
  sum = new bn(0);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.output)
      return new bn(0);

    age = input.output.getConfirmations(height);

    if (age === -1)
      age = 0;

    if (age !== 0)
      age += 1;

    sum.iadd(input.output.value.muln(age));
  }

  return sum.divn(size);
};

TX.prototype.isFree = function isFree(size) {
  var priority;

  if (!this.hasPrevout())
    return false;

  size = size || this.maxSize();

  if (size >= constants.tx.maxFreeSize)
    return false;

  priority = this.getPriority();

  return priority.cmp(constants.tx.freeThreshold) > 0;
};

TX.prototype.getHeight = function getHeight() {
  if (this.height !== -1)
    return this.height;

  if (!this.chain)
    return -1;

  return this.block ? this.chain.getHeight(this.block) : -1;
};

TX.prototype.getConfirmations = function getConfirmations(height) {
  var top, height;

  if (height == null) {
    if (!this.chain)
      return 0;

    top = this.chain.height;
  } else {
    top = height;
  }

  height = this.height;

  if (height === -1)
    return 0;

  if (top < height)
    return 1;

  return top - height + 1;
};

TX.prototype.getValue = function getValue() {
  return this.getOutputValue();
};

TX.prototype.hasType = function hasType(type) {
  for (var i = 0; i < this.inputs.length; i++) {
    if (bcoin.script.getInputType(this.inputs[i].script) === type)
      return true;
  }
  for (var i = 0; i < this.outputs.length; i++) {
    if (bcoin.script.getType(this.outputs[i].script) === type)
      return true;
  }
  return false;
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
  return this.getValue();
});

TX.prototype.__defineGetter__('confirmations', function() {
  return this.getConfirmations();
});

TX.prototype.__defineGetter__('priority', function() {
  return this.getPriority();
});

TX.prototype.inspect = function inspect() {
  var copy = bcoin.tx(this);
  copy.__proto__ = null;
  if (this.block)
    copy.block = this.block;
  delete copy._raw;
  delete copy._chain;
  delete copy.requiredFunds;
  copy.hash = this.hash('hex');
  copy.rhash = this.rhash;
  copy.rblock = this.rblock;
  copy.value = utils.btc(this.getValue());
  copy.fee = utils.btc(this.getFee());
  copy.confirmations = this.getConfirmations();
  copy.priority = this.getPriority().toString(10);
  copy.date = new Date((copy.ts || 0) * 1000).toISOString();
  return copy;
};

TX.prototype.toJSON = function toJSON(coins) {
  // Compact representation
  return {
    v: 1,
    type: 'tx',
    ts: this.ts,
    ps: this.ps,
    block: this.block,
    height: this.height,
    network: this.network,
    relayedBy: this.relayedBy,
    changeIndex: this.changeIndex,
    coins: coins ? this.inputs.map(function(input) {
      return input.output ? input.output.toJSON() : null;
    }) : null,
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

  data.changeIndex = json.changeIndex;

  data._raw = raw;
  data._size = raw.length;

  tx = new TX(data);
  tx.height = json.height;
  tx.ts = json.ts;
  tx.block = json.block || null;
  tx.ps = json.ps;

  if (json.coins) {
    json.coins.forEach(function(output, i) {
      if (!output)
        return;

      tx.inputs[i].output = bcoin.coin.fromJSON(output);
    });
  }

  return tx;
};

TX.prototype.toRaw = function toRaw(enc) {
  var data;

  if (this.isStatic() && this._raw)
    data = this._raw;
  else
    data = new Buffer(this.render());

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

TX.fromRaw = function fromRaw(data, enc) {
  var parser = new bcoin.protocol.parser();

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  if (Array.isArray(data))
    data = new Buffer(data);

  return new bcoin.tx(parser.parseTX(data));
};

/**
 * Expose
 */

module.exports = TX;

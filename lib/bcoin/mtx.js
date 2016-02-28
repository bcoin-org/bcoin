/**
 * mtx.js - mutable transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;

/**
 * MTX
 */

function MTX(options) {
  if (!(this instanceof MTX))
    return new MTX(options);

  if (!options)
    options = {};

  this.options = options;

  this.type = 'mtx';
  this.version = options.version || 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = 0;
  this.ts = 0;
  this.block = null;
  this.index = -1;

  this._hash = null;
  this._whash = null;
  this._raw = null;
  this._size = 0;
  this._offset = 0;
  this._cost = 0;

  this.height = -1;

  this._chain = options.chain;

  if (options.inputs) {
    options.inputs.forEach(function(input) {
      this.addInput(input);
    }, this);
  }

  if (options.outputs) {
    options.outputs.forEach(function(output) {
      this.addOutput(output);
    }, this);
  }

  this.changeIndex = options.changeIndex != null ? options.changeIndex : -1;
  this.ps = this.ts === 0 ? utils.now() : 0;
}

utils.inherits(MTX, bcoin.tx);

MTX.prototype.clone = function clone() {
  var tx = new MTX(this);

  tx.inputs = tx.inputs.map(function(input) {
    input.script = input.script.slice();
    input.witness = input.witness.slice();
    return input;
  });

  tx.outputs = tx.outputs.map(function(output) {
    output.script = output.script.slice();
    return output;
  });

  return tx;
};

MTX.prototype.hash = function hash(enc) {
  var hash = utils.dsha256(this.render());
  return enc === 'hex' ? utils.toHex(hash) : hash;
};

MTX.prototype.witnessHash = function hash(enc) {
  var hash = utils.dsha256(this.renderWitness());
  return enc === 'hex' ? utils.toHex(hash) : hash;
};

MTX.prototype.render = function render() {
  return bcoin.protocol.framer.tx(this);
};

MTX.prototype.renderWitness = function renderWitness() {
  return bcoin.protocol.framer.witnessTX(this);
};

MTX.prototype.getSize = function getSize() {
  return this.render().length;
};

MTX.prototype.getCost = function getCost() {
  return this.renderWitness()._cost;
};

MTX.prototype.addInput = function addInput(options, index) {
  var input, i;

  if (options instanceof MTX)
    options = bcoin.coin(options, index);

  if (options instanceof bcoin.coin) {
    options = {
      prevout: { hash: options.hash, index: options.index },
      output: options
    };
  }

  assert(options.prevout);

  // i = this._inputIndex(options.prevout.hash, options.prevout.index);
  // assert(i === -1);

  input = bcoin.input(options, this);

  this.inputs.push(input);

  return this;
};

MTX.prototype.scriptInput = function scriptInput(index, addr) {
  var input, prev, n, i, redeemScript, witnessScript, vector, dummy;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.output);

  // Optimization: Don't bother with any below
  // calculation if the output is already templated.
  // Just say this is "our" output.
  if (input.script.length || input.witness.length)
    return true;

  // Optimization: test output against the
  // address map to avoid unnecessary calculation.
  // A hash table lookup may be faster than all
  // the nonsense below.
  if (!addr.ownOutput(input.output))
    return false;

  // Get the previous output's script
  prev = input.output.script;

  // This is easily the hardest part about building a transaction
  // with segwit: figuring out where the redeem script and witness
  // redeem scripts go.
  if (bcoin.script.isScripthash(prev)) {
    if (addr.program && utils.isEqual(prev[1], addr.programHash)) {
      // Witness program nested in regular P2SH.
      redeemScript = addr.program;
      vector = input.witness;
      dummy = new Buffer([]);
      assert(addr.program[0] === 0, 'Non-zero version passed to address.');
      if (addr.program.length === 34) {
        // P2WSH nested within pay-to-scripthash
        // (it had to be this complicated, didn't it?)
        witnessScript = addr.script;
        prev = bcoin.script.decode(addr.script);
      } else if (addr.program.length === 22) {
        // P2WPKH nested within pay-to-scripthash.
        prev = bcoin.script.createPubkeyhash(addr.keyHash);
      } else {
        assert(false, 'Unknown program data length passed to address.');
      }
    } else if (addr.script && utils.isEqual(prev[1], addr.scriptHash160)) {
      // Regular P2SH.
      redeemScript = addr.script;
      prev = bcoin.script.decode(addr.script);
      vector = input.script;
      dummy = 0;
    } else {
      return false;
    }
  } else if (bcoin.script.isWitnessProgram(prev)) {
    // Witness program.
    vector = input.witness;
    dummy = new Buffer([]);

    if (prev[0] !== 0)
      return false;

    if (prev[1].length === 32) {
      // Bare P2WPSH.
      if (!addr.script || !utils.isEqual(prev[1], addr.scriptHash256))
        return false;

      witnessScript = addr.script;
      prev = bcoin.script.decode(addr.script);
    } else if (prev[1].length === 20) {
      // Bare P2WPKH.
      if (!utils.isEqual(prev[1], addr.keyHash))
        return false;

      prev = bcoin.script.createPubkeyhash(prev[1]);
    } else {
      // Bare... who knows?
      return false;
    }
  } else {
    // Wow, a normal output! Praise be to Jengus and Gord.
    vector = input.script;
    dummy = 0;
  }

  if (bcoin.script.isPubkey(prev)) {
    // P2PK
    if (!utils.isEqual(prev[0], addr.publicKey))
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    vector[0] = dummy;
  } else if (bcoin.script.isPubkeyhash(prev)) {
    // P2PKH
    if (!utils.isEqual(prev[2], addr.keyHash))
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    vector[0] = dummy;
    vector[1] = addr.publicKey;
  } else if (bcoin.script.isMultisig(prev)) {
    // Multisig
    for (i = 0; i < prev.length; i++) {
      if (utils.isEqual(prev[i], addr.publicKey))
        break;
    }

    if (i === prev.length)
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    vector[0] = dummy;

    // Grab `n` value (number of keys).
    n = prev[prev.length - 2];

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      vector[i + 1] = dummy;
  } else {
    for (i = 0; i < prev.length; i++) {
      if (utils.isEqual(prev[i], addr.publicKey))
        break;
    }

    if (i === prev.length)
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    // Likely a non-standard scripthash multisig
    // input. Determine n value by counting keys.
    // Also, only allow nonstandard types for
    // scripthash.
    vector[0] = dummy;

    // Fill script with `n` signature slots.
    for (i = 0; i < prev.length; i++) {
      if (bcoin.script.isKey(prev[i]))
        vector[i + 1] = dummy;
    }
  }

  // P2SH requires the redeem
  // script after signatures.
  if (redeemScript)
    input.script.push(redeemScript);

  // P2WSH requires the witness
  // script after signatures.
  if (witnessScript)
    input.witness.push(witnessScript);

  return true;
};

MTX.prototype.createSignature = function createSignature(index, prev, key, type) {
  var prev, hash, signature;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (type == null)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, prev, type);

  // Sign the transaction with our one input
  signature = bcoin.script.sign(hash, key, type);

  // Something is broken if this doesn't work:
  // assert(bcoin.script.checksig(hash, signature, key), 'BUG: Verify failed.');

  return signature;
};

MTX.prototype.signInput = function signInput(index, addr, type) {
  var input, prev, signature, ki, signatures, i;
  var len, m, n, keys, vector, dummy;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.output);

  // Get the previous output's subscript
  prev = input.output.script;

  vector = input.script;
  len = vector.length;
  dummy = 0;

  // We need to grab the redeem script when
  // signing p2sh transactions.
  if (bcoin.script.isScripthash(prev)) {
    prev = bcoin.script.getRedeem(input.script);
    len = vector.length - 1;
  }

  // If the output script is a witness program,
  // we have to switch the vector to the witness
  // and potentially alter the length. Note that
  // witnesses are stack items, so the `dummy`
  // _has_ to be an empty buffer (what OP_0
  // pushes onto the stack).
  if (bcoin.script.isWitnessScripthash(prev)) {
    prev = bcoin.script.getRedeem(input.witness);
    vector = input.witness;
    len = vector.length - 1;
    dummy = new Buffer([]);
  } else if (bcoin.script.isWitnessPubkeyhash(prev)) {
    prev = bcoin.script.createPubkeyhash(prev[1]);
    vector = input.witness;
    len = vector.length;
    dummy = new Buffer([]);
  }

  // Create our signature.
  signature = this.createSignature(index, prev, addr.key, type);

  // Add signatures.
  if (bcoin.script.isPubkey(prev)) {
    // P2PK

    // Already signed.
    if (bcoin.script.isSignature(vector[0]))
      return true;

    // Make sure the pubkey is ours.
    if (!utils.isEqual(addr.publicKey, prev[0]))
      return false;

    vector[0] = signature;

    return true;
  }

  if (bcoin.script.isPubkeyhash(prev)) {
    // P2PKH

    // Already signed.
    if (bcoin.script.isSignature(vector[0]))
      return true;

    // Make sure the pubkey hash is ours.
    if (!utils.isEqual(addr.keyHash, prev[2]))
      return false;

    vector[0] = signature;

    return true;
  }

  if (bcoin.script.isMultisig(prev)) {
    // Multisig

    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = prev.slice(1, -2);

    // Grab `m` value (number of sigs required).
    m = prev[0];

    // Grab `n` value (number of keys).
    n = prev[prev.length - 2];
  } else {
    // Only allow non-standard signing for
    // scripthash.
    if (len !== vector.length - 1)
      return false;

    keys = [];

    for (i = 0; i < prev.length; i++) {
      if (bcoin.script.isKey(prev[i]))
        keys.push(prev[i]);
    }

    // We don't know what m is, so
    // we can never finalize the signatures.
    m = keys.length;
    n = keys.length;
  }

  // Something is very wrong here. Abort.
  if (len - 1 > n)
    return false;

  // Count the number of current signatures.
  signatures = 0;
  for (i = 1; i < len; i++) {
    if (bcoin.script.isSignature(vector[i]))
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
    vector.splice(len, 0, dummy);
    len++;
  }

  // Find the key index so we can place
  // the signature in the same index.
  for (ki = 0; ki < keys.length; ki++) {
    if (utils.isEqual(addr.publicKey, keys[ki]))
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
    if (bcoin.script.isZero(vector[ki])) {
      vector[ki] = signature;
      signatures++;
    }
  }

  // All signatures added. Finalize.
  if (signatures >= m) {
    // Remove empty slots left over.
    for (i = len - 1; i >= 1; i--) {
      if (bcoin.script.isZero(vector[i])) {
        vector.splice(i, 1);
        len--;
      }
    }

    // Remove signatures which are not required.
    // This should never happen except when dealing
    // with implementations that potentially handle
    // signature slots differently.
    while (signatures > m) {
      vector.splice(len - 1, 1);
      signatures--;
      len--;
    }

    // Sanity checks.
    assert.equal(signatures, m);
    assert.equal(len - 1, m);
  }

  return signatures === m;
};

MTX.prototype.sign = function sign(index, addr, type) {
  var input;

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  input = this.inputs[index];
  assert(input);

  // Build script for input
  if (!this.scriptInput(index, addr))
    return false;

  // Sign input
  if (!this.signInput(index, addr, type))
    return false;

  return true;
};

MTX.prototype.addOutput = function addOutput(obj, value) {
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

  output = bcoin.output(options, this);

  this.outputs.push(output);

  this.scriptOutput(this.outputs.length - 1, options);

  return this;
};

MTX.prototype.scriptOutput = function scriptOutput(index, options) {
  var output, script, keys, m, n, hash, flags, address;

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
    keys = options.keys.map(utils.ensureBuffer);

    m = options.m;
    n = options.n || keys.length;

    if (!(m >= 1 && m <= n))
      return;

    if (!(n >= 1 && n <= (options.scriptHash ? 15 : 3)))
      return;

    script = bcoin.script.createMultisig(keys, m, n);
  } else if (options.address) {
    address = bcoin.address.parse(options.address);

    if (!address)
      throw new Error(options.address + ' is not a valid address.');

    if (address.type === 'pubkeyhash')
      script = bcoin.script.createPubkeyhash(address.hash);
    else if (address.type === 'scripthash')
      script = bcoin.script.createScripthash(address.hash);
    else if (address.version !== -1)
      script = bcoin.script.createWitnessProgram(address.version, address.hash);
    else
      throw new Error('Cannot parse address: ' + options.address);
  } else if (options.key) {
    // P2PK Transaction
    // [pubkey] checksig
    script = [
      utils.ensureBuffer(options.key),
      'checksig'
    ];
  } else if (options.flags) {
    // Nulldata Transaction
    // return [data]
    flags = options.flags;
    if (typeof flags === 'string')
      flags = new Buffer(flags, 'ascii');
    assert(Buffer.isBuffer(flags));
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

MTX.prototype.maxSize = function maxSize(maxM, maxN) {
  var copy = this.clone();
  var i, j, input, total, size, prev, m, n;

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
    prev = input.output.script;

    // If we have access to the redeem script,
    // we can use it to calculate size much easier.
    if (this.inputs[i].script.length && bcoin.script.isScripthash(prev)) {
      prev = bcoin.script.getRedeem(this.inputs[i].script);
      // Need to add the redeem script size
      // here since it will be ignored by
      // the isMultisig clause.
      // OP_PUSHDATA2 [redeem]
      size += 3 + bcoin.script.getSize(prev);
    }

    if (bcoin.script.isPubkey(prev)) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (bcoin.script.isPubkeyhash(prev)) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
    } else if (bcoin.script.isMultisig(prev)) {
      // Bare Multisig
      // Get the previous m value:
      m = prev[0];
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
    } else if (bcoin.script.isScripthash(prev)) {
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
      for (j = 0; j < prev.length; j++) {
        if (bcoin.script.isKey(prev[j]))
          size += 1 + 73;
      }
    }

    // Byte for varint size of input script
    size += utils.sizeIntv(size);

    total += size;
  }

  return total;
};

MTX.prototype.selectCoins = function selectCoins(unspent, options) {
  var self = this;
  var tx = this.clone();
  var outputValue = tx.getOutputValue();
  var totalkb = 1;
  var chosen = [];
  var lastAdded = 0;
  var minFee = constants.tx.minFee;
  var dustThreshold = constants.tx.dustThreshold;
  var i, size, newkb, change;
  var fee;

  assert(tx.inputs.length === 0);

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
      // Add new inputs until MTX will have enough
      // funds to cover both minimum post cost
      // and fee.
      tx.addInput(unspent[i]);
      chosen.push(unspent[i]);
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
    // calculate maximum MTX size.
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
    chosen = null;
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
        chosen = null;
    }
  }

  // Return necessary inputs and change.
  return {
    coins: chosen,
    change: change,
    fee: fee,
    total: total(),
    kb: totalkb
  };
};

MTX.prototype.fill = function fill(unspent, options) {
  var result, err;

  if (!options || typeof options !== 'object') {
    options = {
      changeAddress: arguments[1],
      fee: arguments[2]
    };
  }

  assert(unspent);
  assert(options.changeAddress);

  result = this.selectCoins(unspent, options);

  if (!result.coins) {
    err = new Error('Could not fill transaction');
    err.requiredFunds = result.total;
    throw err;
  }

  result.coins.forEach(function(coin) {
    this.addInput(coin);
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
MTX.prototype.sortMembers = function sortMembers() {
  var changeOutput;

  if (this.changeIndex !== -1) {
    changeOutput = this.outputs[this.changeIndex];
    assert(changeOutput);
  }

  this.inputs = this.inputs.slice().sort(function(a, b) {
    var h1 = new Buffer(a.prevout.hash, 'hex');
    var h2 = new Buffer(b.prevout.hash, 'hex');

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

MTX.prototype.getTargetLocktime = function getTargetLocktime() {
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

MTX.prototype.avoidFeeSniping = function avoidFeeSniping(height) {
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

MTX.prototype.setLocktime = function setLocktime(locktime) {
  var i, input;

  this.locktime = locktime;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence === 0xffffffff)
      input.sequence = 0;
  }
};

MTX.prototype.increaseFee = function increaseFee(unspent, address, fee) {
  var i, input, result;

  this.inputs.length = 0;

  if (this.changeIndex !== -1)
    this.outputs.splice(this.changeIndex, 1);

  if (!fee)
    fee = this.getFee().add(new bn(10000));

  result = this.fill(unspent, address, fee);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.sequence = 0xffffffff - 1;
  }
};

MTX.prototype.toCompact = function toCompact(coins) {
  return {
    type: 'tx',
    block: this.block,
    height: this.height,
    ts: this.ts,
    ps: this.ps,
    changeIndex: this.changeIndex,
    coins: coins ? this.inputs.map(function(input) {
      return input.output ? input.output.toRaw('hex') : null;
    }) : null,
    tx: utils.toHex(this.render())
  };
};

MTX._fromCompact = function _fromCompact(json) {
  var raw, data, tx;

  assert.equal(json.type, 'tx');

  raw = new Buffer(json.tx, 'hex');
  data = bcoin.protocol.parser.parseTX(raw);

  data.height = json.height;
  data.block = json.block;
  data.ts = json.ts;
  data.ps = json.ps;
  data.changeIndex = json.changeIndex;

  if (json.coins) {
    json.coins.forEach(function(output, i) {
      if (!output)
        return;

      data.inputs[i].output = bcoin.coin._fromRaw(output, 'hex');
    });
  }

  return data;
};

MTX.fromCompact = function fromCompact(json) {
  return new MTX(MTX._fromCompact(json));
};

MTX.prototype.toJSON = function toJSON() {
  return {
    type: 'mtx',
    hash: utils.revHex(this.hash('hex')),
    witnessHash: utils.revHex(this.witnessHash('hex')),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    changeIndex: this.changeIndex,
    version: this.version,
    inputs: this.inputs.map(function(input) {
      return input.toJSON();
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON();
    }),
    locktime: this.locktime
  };
};

MTX._fromJSON = function fromJSON(json) {
  return {
    block: json.block ? utils.revHex(json.block) : null,
    height: json.height,
    ts: json.ts,
    ps: json.ps,
    changeIndex: json.changeIndex,
    version: json.version,
    inputs: json.inputs.map(function(input) {
      return bcoin.input._fromJSON(input);
    }),
    outputs: json.outputs.map(function(output) {
      return bcoin.output._fromJSON(output);
    }),
    locktime: json.locktime
  };
};

MTX.fromJSON = function fromJSON(json) {
  return new MTX(MTX._fromJSON(json));
};

MTX.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

MTX._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseTX(data);
};

MTX.fromRaw = function fromRaw(data, enc) {
  return new MTX(MTX._fromRaw(data, enc));
};

MTX.fromTX = function fromTX(tx) {
  var mtx = new bcoin.tx({
    ts: tx.ts,
    block: tx.block,
    height: tx.height,
    version: tx.version,
    inputs: tx.inputs.map(function(input) {
      input.script = input.script.slice();
      return input;
    }),
    outputs: tx.outputs.map(function(output) {
      output.script = output.script.slice();
      return output;
    }),
    locktime: tx.locktime
  });
  mtx.ps = tx.ps;
  return mtx;
};

MTX.prototype.toTX = function toTX() {
  var tx = new bcoin.tx({
    ts: this.ts,
    block: this.block,
    height: this.height,
    version: this.version,
    inputs: this.inputs.map(function(input) {
      input.script = input.script.slice();
      return input;
    }),
    outputs: this.outputs.map(function(output) {
      output.script = output.script.slice();
      return output;
    }),
    locktime: this.locktime
  });
  return tx;
};

/**
 * Expose
 */

module.exports = MTX;

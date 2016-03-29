/**
 * mtx.js - mutable transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var Script = bcoin.script;
var Witness = bcoin.script.witness;
var opcodes = constants.opcodes;

/**
 * MTX
 */

function MTX(options) {
  if (!(this instanceof MTX))
    return new MTX(options);

  if (!options)
    options = {};

  this.options = options;

  this.type = 'tx';
  this.version = options.version || 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = 0;
  this.ts = 0;
  this.block = null;
  this.index = -1;
  this.ps = this.ts === 0 ? utils.now() : 0;
  this.changeIndex = options.changeIndex != null ? options.changeIndex : -1;

  this._hash = null;
  this._whash = null;
  this._raw = null;
  this._size = 0;
  this._witnessSize = 0;

  this.height = -1;

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
}

utils.inherits(MTX, bcoin.tx);

MTX.prototype.clone = function clone() {
  return new MTX(this);
};

MTX.prototype.hash = function hash(enc) {
  var hash = utils.dsha256(this.renderNormal());
  return enc === 'hex' ? utils.toHex(hash) : hash;
};

MTX.prototype.witnessHash = function witnessHash(enc) {
  var hash;

  if (this.isCoinbase()) {
    return enc === 'hex'
      ? utils.toHex(constants.zeroHash)
      : new Buffer(constants.zeroHash);
  }

  if (!this.hasWitness())
    return this.hash(enc);

  hash = utils.dsha256(this.renderWitness());

  return enc === 'hex' ? utils.toHex(hash) : hash;
};

MTX.prototype.render = function render() {
  return this.getRaw();
};

MTX.prototype.renderNormal = function renderNormal() {
  return bcoin.protocol.framer.tx(this);
};

MTX.prototype.renderWitness = function renderWitness() {
  return bcoin.protocol.framer.witnessTX(this);
};

MTX.prototype.getRaw = function getRaw() {
  if (this.hasWitness())
    return bcoin.protocol.framer.witnessTX(this);

  return bcoin.protocol.framer.tx(this);
};

MTX.prototype.getSize = function getSize() {
  return this.getRaw().length;
};

MTX.prototype.getVirtualSize = function getVirtualSize() {
  var raw = this.getRaw();
  var size = raw.length;
  var witnessSize = raw._witnessSize;
  var base = size - witnessSize;

  return (base * 4 + witnessSize + 3) / 4 | 0;
};

MTX.prototype.addInput = function addInput(options, index) {
  var input;

  if (options instanceof MTX)
    options = bcoin.coin(options, index);

  if (options instanceof bcoin.coin) {
    options = {
      prevout: { hash: options.hash, index: options.index },
      coin: options
    };
  }

  assert(options.prevout);

  // i = this._inputIndex(options.prevout.hash, options.prevout.index);
  // assert(i === -1);

  input = bcoin.input(options, this);

  if (options.script instanceof bcoin.script)
    input.script = options.script.clone();

  if (options.witness instanceof bcoin.script.witness)
    input.witness = options.witness.clone();

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
  assert(input.coin);

  // Optimization: Don't bother with any below
  // calculation if the output is already templated.
  // Just say this is "our" output.
  if (input.script.code.length || input.witness.items.length)
    return true;

  // Optimization: test output against the
  // address map to avoid unnecessary calculation.
  // A hash table lookup may be faster than all
  // the nonsense below.
  if (!addr.ownOutput(input.coin))
    return false;

  // Get the previous output's script
  prev = input.coin.script;

  // This is easily the hardest part about building a transaction
  // with segwit: figuring out where the redeem script and witness
  // redeem scripts go.
  if (prev.isScripthash()) {
    if (addr.program && utils.isEqual(prev.code[1], addr.programHash)) {
      // Witness program nested in regular P2SH.
      redeemScript = addr.program.encode();
      vector = input.witness.items;
      dummy = new Buffer([]);
      assert(addr.program.code[0] === opcodes.OP_0, 'Non-zero version passed to address.');
      if (addr.program.code[1].length === 32) {
        // P2WSH nested within pay-to-scripthash
        // (it had to be this complicated, didn't it?)
        witnessScript = addr.script.encode();
        prev = addr.script;
      } else if (addr.program.code[1].length === 20) {
        // P2WPKH nested within pay-to-scripthash.
        prev = Script.createPubkeyhash(addr.keyHash);
      } else {
        assert(false, 'Unknown program data length passed to address.');
      }
    } else if (addr.script && utils.isEqual(prev.code[1], addr.scriptHash160)) {
      // Regular P2SH.
      redeemScript = addr.script.encode();
      vector = input.script.code;
      prev = addr.script;
      dummy = opcodes.OP_0;
    } else {
      return false;
    }
  } else if (prev.isWitnessProgram()) {
    // Witness program.
    vector = input.witness.items;
    dummy = new Buffer([]);

    if (prev.code[0] !== opcodes.OP_0)
      return false;

    if (prev.code[1].length === 32) {
      // Bare P2WSH.
      if (!addr.script || !utils.isEqual(prev.code[1], addr.scriptHash256))
        return false;

      witnessScript = addr.script.encode();
      prev = addr.script;
    } else if (prev.code[1].length === 20) {
      // Bare P2WPKH.
      if (!utils.isEqual(prev.code[1], addr.keyHash))
        return false;

      prev = Script.createPubkeyhash(prev.code[1]);
    } else {
      // Bare... who knows?
      return false;
    }
  } else {
    // Wow, a normal output! Praise be to Jengus and Gord.
    vector = input.script.code;
    dummy = opcodes.OP_0;
  }

  if (prev.isPubkey()) {
    // P2PK
    if (!utils.isEqual(prev.code[0], addr.publicKey))
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    vector[0] = dummy;
  } else if (prev.isPubkeyhash()) {
    // P2PKH
    if (!utils.isEqual(prev.code[2], addr.keyHash))
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    vector[0] = dummy;
    vector[1] = addr.publicKey;
  } else if (prev.isMultisig()) {
    // Multisig
    if (utils.indexOf(prev.code, addr.publicKey) === -1)
      return false;

    // Already has a script template (at least)
    if (vector.length)
      return true;

    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    vector[0] = dummy;

    // Grab `n` value (number of keys).
    n = Script.getSmall(prev.code[prev.code.length - 2]);

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      vector[i + 1] = dummy;
  } else {
    if (utils.indexOf(prev.code, addr.publicKey) === -1)
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
    for (i = 0; i < prev.code.length; i++) {
      if (Script.isKey(prev.code[i]))
        vector[i + 1] = dummy;
    }
  }

  // P2SH requires the redeem
  // script after signatures.
  if (redeemScript)
    input.script.code.push(redeemScript);

  // P2WSH requires the witness
  // script after signatures.
  if (witnessScript)
    input.witness.items.push(witnessScript);

  return true;
};

MTX.prototype.createSignature = function createSignature(index, prev, key, type, version) {
  var hash, signature;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (type == null)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, prev, type, version);

  // Sign the transaction with our one input
  signature = Script.sign(hash, key, type);

  // Something is broken if this doesn't work:
  // assert(Script.checksig(hash, signature, key), 'BUG: Verify failed.');

  return signature;
};

MTX.prototype.signInput = function signInput(index, addr, type) {
  var input, prev, signature, ki, signatures, i;
  var len, m, n, keys, vector, dummy, version;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.coin);

  // Get the previous output's subscript
  prev = input.coin.script;

  vector = input.script.code;
  len = vector.length;
  dummy = opcodes.OP_0;
  version = 0;

  // We need to grab the redeem script when
  // signing p2sh transactions.
  if (prev.isScripthash()) {
    prev = input.script.getRedeem();
    len = vector.length - 1;
  }

  // If the output script is a witness program,
  // we have to switch the vector to the witness
  // and potentially alter the length. Note that
  // witnesses are stack items, so the `dummy`
  // _has_ to be an empty buffer (what OP_0
  // pushes onto the stack).
  if (prev.isWitnessScripthash()) {
    prev = input.witness.getRedeem();
    vector = input.witness.items;
    len = vector.length - 1;
    dummy = new Buffer([]);
    version = 1;
  } else if (prev.isWitnessPubkeyhash()) {
    prev = Script.createPubkeyhash(prev.code[1]);
    vector = input.witness.items;
    len = vector.length;
    dummy = new Buffer([]);
    version = 1;
  }

  // Create our signature.
  signature = this.createSignature(index, prev, addr.key, type, version);

  // Add signatures.
  if (prev.isPubkey()) {
    // P2PK

    // Already signed.
    if (Script.isSignature(vector[0]))
      return true;

    // Make sure the pubkey is ours.
    if (!utils.isEqual(addr.publicKey, prev.code[0]))
      return false;

    vector[0] = signature;

    return true;
  }

  if (prev.isPubkeyhash()) {
    // P2PKH

    // Already signed.
    if (Script.isSignature(vector[0]))
      return true;

    // Make sure the pubkey hash is ours.
    if (!utils.isEqual(addr.keyHash, prev.code[2]))
      return false;

    vector[0] = signature;

    return true;
  }

  if (prev.isMultisig()) {
    // Multisig

    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = prev.code.slice(1, -2);

    // Grab `m` value (number of sigs required).
    m = Script.getSmall(prev.code[0]);

    // Grab `n` value (number of keys).
    n = Script.getSmall(prev.code[prev.code.length - 2]);
  } else {
    // Only allow non-standard signing for
    // scripthash.
    if (len !== vector.length - 1)
      return false;

    keys = [];

    for (i = 0; i < prev.code.length; i++) {
      if (Script.isKey(prev.code[i]))
        keys.push(prev.code[i]);
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
    if (Script.isSignature(vector[i]))
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
  ki = utils.indexOf(keys, addr.publicKey);

  // Our public key is not in the prev_out
  // script. We tried to sign a transaction
  // that is not redeemable by us.
  if (ki === -1)
    return false;

  // Offset key index by one to turn it into
  // "sig index". Accounts for OP_0 byte at
  // the start.
  ki++;

  // Add our signature to the correct slot
  // and increment the total number of
  // signatures.
  if (ki < len && signatures < m) {
    if (Script.isZero(vector[ki])) {
      vector[ki] = signature;
      signatures++;
    }
  }

  // All signatures added. Finalize.
  if (signatures >= m) {
    // Remove empty slots left over.
    for (i = len - 1; i >= 1; i--) {
      if (Script.isZero(vector[i])) {
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

MTX.prototype.isSigned = function isSigned(m) {
  var i, input, prev, vector, len, j;
  var total = 0;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    // We can't check for signatures unless
    // we have the previous output.
    if (!input.coin)
      return false;

    // Get the prevout's subscript
    prev = input.coin.script;

    // Script length, needed for multisig
    vector = input.script.code;
    len = vector.length;

    // We need to grab the redeem script when
    // signing p2sh transactions.
    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      len = vector.length - 1;
    }

    // If the output script is a witness program,
    // we have to switch the vector to the witness
    // and potentially alter the length. Note that
    // witnesses are stack items, so the `dummy`
    // _has_ to be an empty buffer (what OP_0
    // pushes onto the stack).
    if (prev.isWitnessScripthash()) {
      prev = input.witness.getRedeem();
      vector = input.witness.items;
      len = vector.length - 1;
    } else if (prev.isWitnessPubkeyhash()) {
      prev = Script.createPubkeyhash(prev.code[1]);
      vector = input.witness.items;
      len = vector.length;
    }

    if (prev.isPubkey()) {
      if (!Script.isSignature(vector[0]))
        return false;
    } else if (prev.isPubkeyhash()) {
      if (!Script.isSignature(vector[0]))
        return false;
    } else if (prev.isMultisig()) {
      // Grab `m` value (number of required sigs).
      m = Script.getSmall(prev.code[0]);

      // Ensure all members are signatures.
      for (j = 1; j < len; j++) {
        if (!Script.isSignature(vector[j]))
          return false;
      }

      // Ensure we have the correct number
      // of required signatures.
      if (len - 1 !== m)
        return false;
    } else {
      for (j = 0; j < vector.length; j++) {
        if (Script.isSignatureEncoding(vector[j]))
          total++;
      }

      if (total !== m)
        return false;
    }
  }

  return true;
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
  var output;

  if (options instanceof bcoin.output)
    return;

  if (typeof index !== 'number')
    index = this.outputs.indexOf(index);

  output = this.outputs[index];
  assert(output);

  if (options.script instanceof bcoin.script)
    output.script = options.script.clone();
  else if (options.script)
    output.script = bcoin.script(options.script);
  else
    output.script = Script.createOutputScript(options);
};

MTX.prototype.maxSize = function maxSize(maxM, maxN) {
  var copy = this.clone();
  var i, j, input, total, size, prev, m, n;
  var witness;

  // Create copy with 0-script inputs
  for (i = 0; i < copy.inputs.length; i++) {
    copy.inputs[i].script = new Script([]);
    copy.inputs[i].witness = new Witness([]);
  }

  total = copy.render().length;

  // Add size for signatures and public keys
  for (i = 0; i < copy.inputs.length; i++) {
    input = copy.inputs[i];
    size = 0;
    witness = false;

    assert(input.coin);

    // Get the previous output's subscript
    prev = input.coin.script;

    // If we have access to the redeem script,
    // we can use it to calculate size much easier.
    if (this.inputs[i].script.code.length && prev.isScripthash()) {
      // Need to add the redeem script size
      // here since it will be ignored by
      // the isMultisig clause.
      // OP_PUSHDATA2 [redeem]
      prev = this.inputs[i].script.getRedeem();
      size += utils.sizeVarint(prev.getSize()) + prev.getSize();
    }

    if (prev.isWitnessProgram()) {
      witness = true;
      // Now calculating vsize. The regular
      // redeem script (if there was one)
      // is now worth 4 points.
      size *= 4;
      if (this.inputs[i].witness.items.length && prev.isWitnessScripthash()) {
        prev = this.inputs[i].witness.getRedeem();
        size += utils.sizeVarint(prev.getSize()) + prev.getSize();
      } else if (prev.isWitnessPubkeyhash()) {
        prev = Script.createPubkeyhash(prev.code[1]);
      }
    }

    if (prev.isPubkey()) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (prev.isPubkeyhash()) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
    } else if (prev.isMultisig()) {
      // Bare Multisig
      // Get the previous m value:
      m = Script.getSmall(prev.code[0]);
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
    } else if (prev.isScripthash()) {
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
      for (j = 0; j < prev.code.length; j++) {
        if (Script.isKey(prev.code[j]))
          size += 1 + 73;
      }
    }

    // Byte for varint size of input script.
    size += utils.sizeVarint(size);

    // Calculate vsize if we're a witness program.
    if (witness)
      size = (size + 3) / 4 | 0;

    total += size;
  }

  return total;
};

MTX.prototype.selectCoins = function selectCoins(coins, options) {
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
    coins = coins.slice().sort(function(a, b) {
      return a.height - b.height;
    });
  } else if (options.selection === 'random' || options.selection === 'all') {
    // Random unspents
    coins = coins.slice().sort(function() {
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

    for (i = lastAdded; i < coins.length; i++) {
      // Add new inputs until MTX will have enough
      // funds to cover both minimum post cost
      // and fee.
      tx.addInput(coins[i]);
      chosen.push(coins[i]);
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

      if (options.free) {
        if (newkb == null && tx.isFree(null, size)) {
          fee = new bn(0);
          break;
        }
      }

      if (options.accurate) {
        newkb = size / 1024;
        fee = new bn(newkb * minFee | 0);
        totalkb = newkb;
      } else {
        newkb = Math.ceil(size / 1024) - totalkb;
        fee.iaddn(newkb * minFee);
        totalkb += newkb;
      }

      // Failed to get enough funds, add more inputs.
      if (!isFull())
        addCoins();
    } while (!isFull() && lastAdded < coins.length);
  }

  if (!isFull()) {
    // Still failing to get enough funds.
    chosen = null;
  } else {
    // How much money is left after filling outputs.
    change = tx.getInputValue().sub(total());

    // Attempt to subtract fee.
    if (options.subtractFee != null) {
      if (typeof options.subtractFee === 'number') {
        i = options.subtractFee;
        assert(tx.outputs[i], 'Subtraction index does not exist.');
        if (tx.outputs[i].value.cmp(fee.addn(dustThreshold)) >= 0)
          tx.outputs[i].value.isub(fee);
        else
          chosen = null;
      } else {
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

MTX.prototype.fill = function fill(coins, options) {
  var self = this;
  var result, err;

  if (!options || typeof options !== 'object') {
    options = {
      changeAddress: arguments[1],
      fee: arguments[2]
    };
  }

  assert(coins);
  assert(options.changeAddress, '`changeAddress` is required.');

  result = this.selectCoins(coins, options);

  if (!result.coins) {
    err = new Error('Could not fill transaction.');
    err.requiredFunds = result.total;
    throw err;
  }

  result.coins.forEach(function(coin) {
    self.addInput(coin);
  });

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
    return utils.cmp(a.encode(), b.encode());
  });

  if (this.changeIndex !== -1) {
    this.changeIndex = this.outputs.indexOf(changeOutput);
    assert(this.changeIndex !== -1);
  }
};

MTX.prototype.avoidFeeSniping = function avoidFeeSniping(height) {
  if (height == null)
    height = network.height;

  if (height === -1)
    height = 0;

  if ((Math.random() * 10 | 0) === 0)
    this.setLocktime(Math.max(0, height - (Math.random() * 100 | 0)));
  else
    this.setLocktime(height);
};

MTX.prototype.setLocktime = function setLocktime(locktime) {
  var i, input;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence === 0xffffffff)
      input.sequence = 0xffffffff - 1;
  }

  this.locktime = locktime;
};

MTX._fromJSON = bcoin.tx._fromJSON;

MTX.fromJSON = function fromJSON(json) {
  return new MTX(MTX._fromJSON(json));
};

MTX._fromRaw = bcoin.tx._fromRaw;

MTX.fromRaw = function fromRaw(data, enc) {
  return new MTX(MTX._fromRaw(data, enc));
};

MTX._fromExtended = bcoin.tx._fromExtended;

MTX.fromExtended = function fromExtended(data, enc) {
  return new MTX(MTX._fromExtended(data, enc));
};

MTX.fromTX = function fromTX(tx) {
  return new MTX(tx);
};

MTX.prototype.toTX = function toTX() {
  return new bcoin.tx(this);
};

MTX.isMTX = function isMTX(obj) {
  return obj
    && Array.isArray(obj.inputs)
    && typeof obj.ps === 'number'
    && typeof obj.changeIndex === 'number'
    && typeof obj.scriptInput === 'function';
};

/**
 * Expose
 */

module.exports = MTX;

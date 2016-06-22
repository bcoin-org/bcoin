/*!
 * mtx.js - mutable transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var Script = bcoin.script;
var opcodes = constants.opcodes;
var HASH160 = constants.ZERO_HASH.slice(0, 20);
var FundingError = bcoin.errors.FundingError;

/**
 * A mutable transaction object.
 * @exports MTX
 * @extends TX
 * @constructor
 * @param {Object} options
 * @param {Number?} options.version
 * @param {Number?} options.ps
 * @param {Number?} options.changeIndex
 * @param {Input[]?} options.inputs
 * @param {Output[]?} options.outputs
 * @property {String} type - "tx" (inv type).
 * @property {Number} version - Transaction version. Note that BCoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Number} flag - Flag field for segregated witness.
 * Always non-zero (1 if not present).
 * @property {Input[]} inputs
 * @property {Output[]} outputs
 * @property {Number} locktime - nLockTime
 * @property {Number} ts - Timestamp of the block the transaction
 * was included in (unix time).
 * @property {Hash|null} block - Hash of the block the transaction
 * was included in.
 * @property {Number} index - Transaction's index in the block tx vector.
 * @property {Number} ps - "Pending Since": The time at which the transaction
 * was first seen. Only non-zero on unconfirmed transactions.
 * @property {Number} changeIndex - Index of the change output (-1 if unknown).
 * @property {Number} height - Height of the block the
 * transaction was included in (-1 if unconfirmed).
 * @property {ReversedHash|null} rblock - Reversed block hash (uint256le).
 * @property {ReversedHash} rhash - Reversed transaction hash (uint256le).
 * @property {ReversedHash} rwhash - Reversed witness
 * transaction hash (uint256le).
 * @property {String} txid - Transaction ID.
 * @property {String} wtxid - Witness transaction ID (Same as txid if no
 * witness is present. All zeroes if coinbase).
 */

function MTX(options) {
  var i;

  if (!(this instanceof MTX))
    return new MTX(options);

  if (!options)
    options = {};

  this.version = options.version || 1;
  this.flag = options.flag || 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = 0;
  this.ts = 0;
  this.block = null;
  this.index = -1;
  this.ps = options.ps != null ? options.ps : utils.now();
  this.changeIndex = options.changeIndex != null ? options.changeIndex : -1;
  this.height = -1;
  this.mutable = true;

  this._hash = null;
  this._whash = null;
  this._raw = null;
  this._size = null;
  this._witnessSize = null;
  this._outputValue = null;
  this._inputValue = null;
  this._hashPrevouts = null;
  this._hashSequence = null;
  this._hashOutputs = null;
  this._lastWitnessSize = 0;

  if (options.inputs) {
    for (i = 0; i < options.inputs.length; i++)
      this.addInput(options.inputs[i]);
  }

  if (options.outputs) {
    for (i = 0; i < options.outputs.length; i++)
      this.addOutput(options.outputs[i]);
  }
}

utils.inherits(MTX, bcoin.tx);

MTX.fromOptions = function fromOptions(options) {
  return new MTX(options);
};

/**
 * Clone the transaction.
 * @returns {MTX}
 */

MTX.prototype.clone = function clone() {
  var tx = new MTX(this);
  tx.locktime = this.locktime;
  tx.ts = this.ts;
  tx.block = this.block;
  tx.index = this.index;
  tx.ps = this.ps;
  tx.height = this.height;
  return tx;
};

/**
 * Add an input to the transaction.
 * @example
 * tx.addInput({ prevout: { hash: ... }, sequence: ... });
 * tx.addInput(prev, prevIndex);
 * tx.addInput(coin);
 * tx.addInput(bcoin.coin.fromTX(prev, prevIndex));
 * @param {Object|TX|Coin} options - Options object, transaction, or coin.
 * @param {Number?} index - Input of output if `options` is a TX.
 */

MTX.prototype.addInput = function addInput(options, index) {
  var input;

  if (options instanceof bcoin.tx)
    options = bcoin.coin.fromTX(options, index);

  if (options instanceof bcoin.coin) {
    assert(typeof options.hash === 'string');
    assert(typeof options.index === 'number');
    options = {
      prevout: { hash: options.hash, index: options.index },
      coin: options
    };
  }

  assert(options.prevout);

  input = bcoin.input(options, true);

  this.inputs.push(input);

  return this;
};

/**
 * Build input script (or witness) templates (with
 * OP_0 in place of signatures).
 * @param {Number} index - Input index.
 * @param {Address} addr - Address used to build. The address
 * must be able to redeem the coin.
 * @returns {Boolean} Whether the script was able to be built.
 * @throws on unavailable coins.
 */

MTX.prototype.scriptInput = function scriptInput(index, addr) {
  var input, prev, n, i, vector, redeemScript, witnessScript;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.coin, 'Coins are not available for scripting.');

  // Optimization: Don't bother with any below
  // calculation if the output is already templated.
  // Just say this is "our" output.
  if (input.script.length !== 0 || input.witness.length !== 0)
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
    if (addr.program && utils.equal(prev.get(1), addr.programHash)) {
      // Witness program nested in regular P2SH.
      redeemScript = addr.program.toRaw();
      vector = input.witness;
      if (addr.program.isWitnessScripthash()) {
        // P2WSH nested within pay-to-scripthash
        // (it had to be this complicated, didn't it?)
        witnessScript = addr.script.toRaw();
        prev = addr.script;
      } else if (addr.program.isWitnessPubkeyhash()) {
        // P2WPKH nested within pay-to-scripthash.
        prev = Script.fromPubkeyhash(addr.keyHash);
      } else {
        assert(false, 'Unknown program.');
      }
    } else if (addr.script && utils.equal(prev.get(1), addr.scriptHash160)) {
      // Regular P2SH.
      redeemScript = addr.script.toRaw();
      vector = input.script;
      prev = addr.script;
    } else {
      return false;
    }
  } else if (prev.isProgram()) {
    // Witness program.
    vector = input.witness;

    if (prev.isWitnessScripthash()) {
      // Bare P2WSH.
      if (!addr.script || !utils.equal(prev.get(1), addr.scriptHash256))
        return false;

      witnessScript = addr.script.toRaw();
      prev = addr.script;
    } else if (prev.isWitnessPubkeyhash()) {
      // Bare P2WPKH.
      if (!utils.equal(prev.get(1), addr.keyHash))
        return false;

      prev = Script.fromPubkeyhash(prev.get(1));
    } else {
      // Bare... who knows?
      return false;
    }
  } else {
    // Wow, a normal output! Praise be to Jengus and Gord.
    vector = input.script;
  }

  if (prev.isPubkey(true)) {
    // P2PK
    if (!utils.equal(prev.get(1), addr.publicKey))
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    vector.set(0, opcodes.OP_0);
  } else if (prev.isPubkeyhash(true)) {
    // P2PKH
    if (!utils.equal(prev.get(2), addr.keyHash))
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    vector.set(0, opcodes.OP_0);
    vector.set(1, addr.publicKey);
  } else if (prev.isMultisig()) {
    // Multisig
    if (prev.indexOf(addr.publicKey) === -1)
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    vector.set(0, opcodes.OP_0);

    // Grab `n` value (number of keys).
    n = prev.getSmall(prev.length - 2);

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      vector.set(i + 1, opcodes.OP_0);
  } else {
    if (prev.indexOf(addr.publicKey) === -1)
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    // Likely a non-standard scripthash multisig
    // input. Determine n value by counting keys.
    // Also, only allow nonstandard types for
    // scripthash.
    vector.set(0, opcodes.OP_0);

    // Fill script with `n` signature slots.
    for (i = 0; i < prev.length; i++) {
      if (Script.isKey(prev.get(i)))
        vector.set(i + 1, opcodes.OP_0);
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

  input.script.compile();
  input.witness.compile();

  return true;
};

/**
 * Create a signature suitable for inserting into scriptSigs/witnesses.
 * @param {Number} index - Index of input being signed.
 * @param {Script} prev - Previous output script or redeem script
 * (in the case of witnesspubkeyhash, this should be the generated
 * p2pkh script).
 * @param {SighashType} type
 * @param {Number} version - Sighash version (0=legacy, 1=segwit).
 * @returns {Buffer} Signature in DER format.
 */

MTX.prototype.createSignature = function createSignature(index, prev, key, type, version) {
  var hash;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (type == null)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, prev, type, version);

  // Sign the transaction with our one input
  return Script.sign(hash, key, type);
};

/**
 * Sign an input.
 * @param {Number} index - Index of input being signed.
 * @param {KeyRing} addr - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 * @throws on unavailable coins.
 */

MTX.prototype.signInput = function signInput(index, addr, key, type) {
  var input, prev, signature, keyIndex, signatures, i;
  var len, m, n, keys, vector, version;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  assert(input.coin, 'Coins are not available for signing.');

  // Get the previous output's script
  prev = input.coin.script;

  vector = input.script;
  len = vector.length;
  version = 0;

  // We need to grab the redeem script when
  // signing p2sh transactions.
  if (prev.isScripthash()) {
    prev = input.script.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
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
    if (!prev)
      throw new Error('Input has not been templated.');
    vector = input.witness;
    len = vector.length - 1;
    version = 1;
  } else if (prev.isWitnessPubkeyhash()) {
    prev = Script.fromPubkeyhash(prev.get(1));
    vector = input.witness;
    len = vector.length;
    version = 1;
  }

  // Create our signature.
  signature = this.createSignature(index, prev, key, type, version);

  // P2PK
  if (prev.isPubkey(true)) {
    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    // Make sure the pubkey is ours.
    if (!utils.equal(addr.publicKey, prev.get(0)))
      return false;

    if (vector.getSmall(0) !== 0)
      throw new Error('Input has not been templated.');

    vector.set(0, signature);
    vector.compile();

    return true;
  }

  // P2PKH
  if (prev.isPubkeyhash(true)) {
    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    // Make sure the pubkey hash is ours.
    if (!utils.equal(addr.keyHash, prev.get(2)))
      return false;

    if (!Script.isKey(vector.get(1)))
      throw new Error('Input has not been templated.');

    vector.set(0, signature);
    vector.compile();

    return true;
  }

  // Multisig
  if (prev.isMultisig()) {
    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = [];

    for (i = 1; i < prev.length - 2; i++)
      keys.push(prev.get(i));

    // Grab `m` value (number of sigs required).
    m = prev.getSmall(0);

    // Grab `n` value (number of keys).
    n = prev.getSmall(prev.length - 2);
  } else {
    // Only allow non-standard signing for
    // scripthash.
    if (len !== vector.length - 1)
      return false;

    keys = [];

    for (i = 0; i < prev.length; i++) {
      if (Script.isKey(prev.get(i)))
        keys.push(prev.get(i));
    }

    // We don't know what m is, so
    // we can never finalize the signatures.
    m = keys.length;
    n = keys.length;
  }

  if (vector.getSmall(0) !== 0)
    throw new Error('Input has not been templated.');

  // Something is very wrong here. Abort.
  if (len - 1 > n)
    return false;

  // Count the number of current signatures.
  signatures = 0;
  for (i = 1; i < len; i++) {
    if (Script.isSignature(vector.get(i)))
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
    vector.insert(len, opcodes.OP_0);
    len++;
  }

  // Find the key index so we can place
  // the signature in the same index.
  keyIndex = utils.indexOf(keys, addr.publicKey);

  // Our public key is not in the prev_out
  // script. We tried to sign a transaction
  // that is not redeemable by us.
  if (keyIndex === -1)
    return false;

  // Offset key index by one to turn it into
  // "sig index". Accounts for OP_0 byte at
  // the start.
  keyIndex++;

  // Add our signature to the correct slot
  // and increment the total number of
  // signatures.
  if (keyIndex < len && signatures < m) {
    if (vector.getSmall(keyIndex) === 0) {
      vector.set(keyIndex, signature);
      signatures++;
    }
  }

  // All signatures added. Finalize.
  if (signatures >= m) {
    // Remove empty slots left over.
    for (i = len - 1; i >= 1; i--) {
      if (vector.getSmall(i) === 0) {
        vector.remove(i);
        len--;
      }
    }

    // Remove signatures which are not required.
    // This should never happen except when dealing
    // with implementations that potentially handle
    // signature slots differently.
    while (signatures > m) {
      vector.remove(len - 1);
      signatures--;
      len--;
    }

    // Sanity checks.
    assert(signatures === m);
    assert(len - 1 === m);
  }

  vector.compile();

  return signatures === m;
};

/**
 * Test whether the transaction is fully-signed.
 * @returns {Boolean}
 */

MTX.prototype.isSigned = function isSigned() {
  var i, input, prev, vector, m, len, j;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    // We can't check for signatures unless
    // we have the previous output.
    if (!input.coin)
      return false;

    // Get the prevout's script
    prev = input.coin.script;

    // Script length, needed for multisig
    vector = input.script;
    len = vector.length;

    // We need to grab the redeem script when
    // signing p2sh transactions.
    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      if (!prev)
        return false;
      len = vector.length - 1;
    }

    // If the output script is a witness program,
    // we have to switch the vector to the witness
    // and potentially alter the length.
    if (prev.isWitnessScripthash()) {
      prev = input.witness.getRedeem();
      if (!prev)
        return false;
      vector = input.witness;
      len = vector.length - 1;
    } else if (prev.isWitnessPubkeyhash()) {
      prev = Script.fromPubkeyhash(prev.get(1));
      vector = input.witness;
      len = vector.length;
    }

    if (prev.isPubkey(true)) {
      if (!Script.isSignature(vector.get(0)))
        return false;
    } else if (prev.isPubkeyhash(true)) {
      if (!Script.isSignature(vector.get(0)))
        return false;
    } else if (prev.isMultisig()) {
      // Grab `m` value (number of required sigs).
      m = prev.getSmall(0);

      // Ensure all members are signatures.
      for (j = 1; j < len; j++) {
        if (!Script.isSignature(vector.get(j)))
          return false;
      }

      // Ensure we have the correct number
      // of required signatures.
      if (len - 1 !== m)
        return false;
    } else {
      return false;
    }
  }

  return true;
};

/**
 * Built input scripts (or witnesses) and sign the inputs.
 * @param {Number} index - Index of input being signed.
 * @param {KeyRing} addr - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 * @throws on unavailable coins.
 */

MTX.prototype.sign = function sign(index, addr, key, type) {
  var input;

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  input = this.inputs[index];
  assert(input);

  // Build script for input
  if (!this.scriptInput(index, addr))
    return false;

  // Sign input
  if (!this.signInput(index, addr, key, type))
    return false;

  return true;
};

/**
 * Add an output.
 * @example
 * tx.addOutput({ address: ..., value: new bn(100000) });
 * tx.addOutput({ address: ..., value: utils.satoshi('0.1') });
 * tx.addOutput(receivingWallet, utils.satoshi('0.1'));
 * @param {Wallet|KeyRing|Object} obj - Wallet, Address,
 * or options (see {@link Script.createOutputScript} for options).
 * @param {Amount?} value - Only needs to be present for non-options.
 */

MTX.prototype.addOutput = function addOutput(address, value) {
  var options, output;

  if ((address instanceof bcoin.wallet)
      || (address instanceof bcoin.keyring)) {
    address = address.getAddress();
  }

  if (typeof address === 'string') {
    options = {
      address: address,
      value: value
    };
  } else {
    options = address;
  }

  output = bcoin.output(options, true);

  if (options.address)
    output.script = Script.fromAddress(options.address);

  this.outputs.push(output);

  return this;
};

/**
 * Test whether the transaction at least
 * has all script templates built.
 * @returns {Boolean}
 */

MTX.prototype.isScripted = function isScripted() {
  var i, input;

  if (this.outputs.length === 0)
    return false;

  if (this.inputs.length === 0)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (input.script.raw.length === 0
        && input.witness.items.length === 0) {
      return false;
    }
  }

  return true;
};

/**
 * Estimate maximum possible size.
 * @param {(Wallet|Object)?} options - Wallet or options object.
 * @param {Number} options.m - Multisig `m` value.
 * @param {Number} options.n - Multisig `n` value.
 * @param {Boolean} force - `maxSize` will just calculate
 * the virtual size instead of _estimating_ it if the
 * templates are already built. If true, this will force
 * estimation of the size.
 * @returns {Number}
 */

MTX.prototype.maxSize = function maxSize(options, force) {
  var scale = constants.WITNESS_SCALE_FACTOR;
  var i, j, input, total, size, prev, m, n, sz;
  var witness, hadWitness, redeem, wallet;

  if (!force && this.isScripted())
    return this.getVirtualSize();

  if (!options)
    options = {};

  if (options instanceof bcoin.wallet)
    options = { wallet: options, m: options.m, n: options.n };

  if (options.wallet)
    wallet = options.wallet;

  function getRedeem(vector, hash) {
    var redeem = vector.getRedeem();
    var address;

    if (redeem)
      return redeem;

    if (!wallet)
      return;

    address = wallet.receiveAddress;

    if (address.program && hash.length === 20)
      return address.program;

    return address.script;
  }

  // Calculate the size, minus the input scripts.
  total = this.getBaseSize();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    size = input.script.getSize();
    total -= utils.sizeVarint(size) + size;
  }

  // Add size for signatures and public keys
  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    size = 0;
    witness = false;
    redeem = null;

    // We're out of luck here.
    // Just assume it's a p2pkh.
    if (!input.coin) {
      total += 110;
      continue;
    }

    // Get the previous output's script
    prev = input.coin.script;

    // If we have access to the redeem script,
    // we can use it to calculate size much easier.
    if (prev.isScripthash()) {
      // Need to add the redeem script size
      // here since it will be ignored by
      // the isMultisig clause.
      // OP_PUSHDATA2 [redeem]
      redeem = getRedeem(input.script, prev.get(1));
      if (redeem) {
        prev = redeem;
        sz = prev.getSize();
        size += bcoin.script.sizePush(sz);
        size += sz;
      }
    }

    if (prev.isProgram()) {
      witness = true;

      // Now calculating vsize.
      if (redeem) {
        // The regular redeem script
        // is now worth 4 points.
        size += utils.sizeVarint(size);
        size *= 4;
      } else {
        // Add one varint byte back
        // for the 0-byte input script.
        size += 1 * 4;
      }

      // Add 2 bytes for flag and marker.
      if (!hadWitness)
        size += 2;

      hadWitness = true;

      if (prev.isWitnessScripthash()) {
        redeem = getRedeem(input.witness, prev.get(1));
        if (redeem) {
          prev = redeem;
          sz = prev.getSize();
          size += utils.sizeVarint(sz);
          size += sz;
        }
      } else if (prev.isWitnessPubkeyhash()) {
        prev = Script.fromPubkeyhash(prev.get(1));
      }
    }

    if (prev.isPubkey(true)) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (prev.isPubkeyhash(true)) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
    } else if (prev.isMultisig()) {
      // Bare Multisig
      // Get the previous m value:
      m = prev.getSmall(0);
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
    } else if (prev.isScripthash() || prev.isWitnessScripthash()) {
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
      m = options.m || 3;
      // n value
      n = options.n || 3;
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
        if (Script.isKey(prev.get(j)))
          size += 1 + 73;
      }
    }

    if (witness) {
      // Calculate vsize if
      // we're a witness program.
      size = (size + scale - 1) / scale | 0;
    } else {
      // Byte for varint
      // size of input script.
      size += utils.sizeVarint(size);
    }

    total += size;
  }

  return total;
};

/**
 * Select necessary coins based on total output value.
 * @param {Coin[]} coins
 * @param {Object?} options
 * @param {String?} options.selection - Coin selection priority. Can
 * be `age`, `random`, or `all`. (default=age).
 * @param {Boolean} options.confirmed - Select only confirmed coins.
 * @param {Boolean} options.round - Whether to round to the nearest
 * kilobyte for fee calculation.
 * See {@link TX#getMinFee} vs. {@link TX#getRoundFee}.
 * @param {Boolean} options.free - Do not apply a fee if the
 * transaction priority is high enough to be considered free.
 * @param {Amount?} options.fee - Use a hard fee rather than calculating one.
 * @param {Rate?} options.rate - Rate used for fee calculation.
 * @param {Number|Boolean} options.subtractFee - Whether to subtract the
 * fee from * existing outputs rather than adding more inputs.
 * @returns {CoinSelection}
 * @throws on not enough funds available.
 * @throws on unable to subtract fee.
 */

MTX.prototype.selectCoins = function selectCoins(coins, options) {
  var chosen = [];
  var index = 0;
  var tx = this.clone();
  var outputValue = tx.getOutputValue();
  var tryFree, size, change, fee;

  if (!options)
    options = {};

  tryFree = options.free;

  // Null the inputs if there are any.
  tx.inputs.length = 0;

  if (!options.selection || options.selection === 'age') {
    // Oldest unspents first
    coins = coins.slice().sort(function(a, b) {
      a = a.height === -1 ? 0x7fffffff : a.height;
      b = b.height === -1 ? 0x7fffffff : b.height;
      return a - b;
    });
  } else if (options.selection === 'random' || options.selection === 'all') {
    // Random unspents
    coins = coins.slice().sort(function() {
      return Math.random() > 0.5 ? 1 : -1;
    });
  }

  function total() {
    if (options.subtractFee != null)
      return outputValue;
    return outputValue + fee;
  }

  function isFull() {
    return tx.getInputValue() >= total();
  }

  function addCoins() {
    var coin;

    while (index < coins.length) {
      coin = coins[index++];

      if (options.confirmed && coin.height === -1)
        continue;

      if (options.height >= 0 && coin.coinbase) {
        if (options.height + 1 < coin.height + constants.tx.COINBASE_MATURITY)
          continue;
      }

      // Add new inputs until TX will have enough
      // funds to cover both minimum post cost
      // and fee.
      tx.addInput(coin);
      chosen.push(coin);

      if (options.selection === 'all')
        continue;

      // Stop once we're full.
      if (isFull())
        break;
    }
  }

  if (options.fee != null) {
    fee = options.fee;

    if (fee > constants.tx.MAX_FEE)
      fee = constants.tx.MAX_FEE;

    // Transfer `total` funds maximum.
    addCoins();
  } else {
    fee = constants.tx.MIN_FEE;

    // Transfer `total` funds maximum.
    addCoins();

    // Add dummy output (for `change`) to
    // calculate maximum TX size.
    tx.addOutput({
      // In case we don't have a change address,
      // use a fake p2pkh output to gauge size.
      script: options.changeAddress
        ? Script.fromAddress(options.changeAddress)
        : Script.fromPubkeyhash(HASH160),
      value: 0
    });

    // Change fee value if it is more than 1024
    // bytes (10000 satoshi for every 1024 bytes).
    do {
      // Calculate max possible size after signing.
      size = tx.maxSize(options, true);

      if (tryFree && options.height >= 0) {
        // Note that this will only work
        // if the mempool's rolling reject
        // fee is zero (i.e. the mempool is
        // not full).
        if (tx.isFree(options.height + 1, size)) {
          fee = 0;
          break;
        }
        tryFree = false;
      }

      if (options.round)
        fee = tx.getRoundFee(size, options.rate);
      else
        fee = tx.getMinFee(size, options.rate);

      if (fee > constants.tx.MAX_FEE)
        fee = constants.tx.MAX_FEE;

      // Failed to get enough funds, add more coins.
      if (!isFull())
        addCoins();
    } while (!isFull() && index < coins.length);
  }

  if (!isFull()) {
    // Still failing to get enough funds.
    throw new FundingError(
      'Not enough funds.',
      tx.getInputValue(),
      total());
  }

  // How much money is left after filling outputs.
  change = tx.getInputValue() - total();

  // Return necessary inputs and change.
  return {
    coins: chosen,
    change: change,
    fee: fee,
    total: total()
  };
};

/**
 * Attempt to subtract a fee from outputs.
 * @param {Amount} fee
 * @param {Number?} index
 */

MTX.prototype.subtractFee = function subtractFee(fee, index) {
  var i, min, output;

  if (typeof index === 'number') {
    output = this.outputs[index];

    if (!output)
      throw new Error('Subtraction index does not exist.');

    min = fee + output.getDustThreshold();

    if (output.value < min)
      throw new Error('Could not subtract fee.');

    output.value -= fee;

    return;
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    min = fee + output.getDustThreshold();
    if (output.value >= min) {
      output.value -= fee;
      break;
    }
  }

  if (i === this.outputs.length)
    throw new Error('Could not subtract fee.');
};

/**
 * Select coins and fill the inputs.
 * @param {Coin[]} coins
 * @param {Object} options - See {@link MTX#selectCoins} options.
 * @returns {Object} See {@link MTX#selectCoins} return value.
 */

MTX.prototype.fill = function fill(coins, options) {
  var result, i, change, changeAddress;

  assert(this.inputs.length === 0, 'TX is already filled.');

  if (!options)
    options = {};

  // Select necessary coins.
  result = this.selectCoins(coins, options);

  // We need a change address.
  changeAddress = options.changeAddress;

  // If change address is not available,
  // send back to one of the coins' addresses.
  for (i = 0; i < result.coins.length && !changeAddress; i++)
    changeAddress = result.coins[i].getAddress();

  // Will only happen in rare cases where
  // we're redeeming all non-standard coins.
  if (!changeAddress)
    throw new Error('No change address available.');

  // Add coins to transaction.
  for (i = 0; i < result.coins.length; i++)
    this.addInput(result.coins[i]);

  // Attempt to subtract fee.
  if (options.subtractFee || options.subtractFee === 0)
    this.subtractFee(result.fee, options.subtractFee);

  // Add a change output.
  this.addOutput({
    address: changeAddress,
    value: result.change
  });

  change = this.outputs[this.outputs.length - 1];

  if (change.isDust(constants.tx.MIN_RELAY)) {
    // Do nothing. Change is added to fee.
    this.outputs.pop();
    this.changeIndex = -1;
    assert.equal(this.getFee(), result.fee + result.change);
  } else {
    this.changeIndex = this.outputs.length - 1;
    assert.equal(this.getFee(), result.fee);
  }

  return result;
};

/**
 * Sort inputs and outputs according to BIP69.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */

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
    var res = a.value - b.value;
    if (res !== 0)
      return res;
    return utils.cmp(a.script.toRaw(), b.script.toRaw());
  });

  if (this.changeIndex !== -1) {
    this.changeIndex = this.outputs.indexOf(changeOutput);
    assert(this.changeIndex !== -1);
  }
};

/**
 * Avoid fee sniping.
 * @param {Number?} [height=network.height] - Current chain height.
 * @see bitcoin/src/wallet/wallet.cpp
 */

MTX.prototype.avoidFeeSniping = function avoidFeeSniping(height) {
  if (height == null)
    height = bcoin.network.get().height;

  if (height === -1)
    height = 0;

  if ((Math.random() * 10 | 0) === 0)
    this.setLocktime(Math.max(0, height - (Math.random() * 100 | 0)));
  else
    this.setLocktime(height);
};

/**
 * Set locktime and sequences appropriately.
 * @param {Number} locktime
 */

MTX.prototype.setLocktime = function setLocktime(locktime) {
  var i, input;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence === 0xffffffff)
      input.sequence = 0xffffffff - 1;
  }

  this.locktime = locktime;
};

/**
 * @see TX.fromJSON
 */

MTX.fromJSON = function fromJSON(json) {
  return new MTX().fromJSON(JSON)._mutable();
};

/**
 * @see TX.fromRaw
 */

MTX.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new MTX().fromRaw(data)._mutable();
};

/**
 * Mark inputs and outputs as mutable.
 * @private
 */

MTX._mutable = function _mutable() {
  var i;
  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].mutable = true;
  for (i = 0; i < this.outputs.length; i++)
    this.outputs[i].mutable = true;
  return this;
};

/**
 * @see TX.fromExtended
 */

MTX.fromExtended = function fromExtended(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new MTX().fromExtended(data)._mutable();
};

/**
 * Convert the MTX to a TX.
 * @returns {TX}
 */

MTX.prototype.toTX = function toTX() {
  return new bcoin.tx(this);
};

/**
 * Test whether an object is an MTX.
 * @param {Object} obj
 * @returns {Boolean}
 */

MTX.isMTX = function isMTX(obj) {
  return obj
    && Array.isArray(obj.inputs)
    && typeof obj.locktime === 'number'
    && typeof obj.scriptInput === 'function';
};

/*
 * Expose
 */

module.exports = MTX;

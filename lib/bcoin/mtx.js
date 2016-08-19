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
var FundingError = bcoin.errors.FundingError;
var TX = bcoin.tx;

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
  if (!(this instanceof MTX))
    return new MTX(options);

  TX.call(this);

  this.mutable = true;
  this.changeIndex = -1;

  if (options)
    this.fromOptions(options);
}

utils.inherits(MTX, TX);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MTX.prototype.fromOptions = function fromOptions(options) {
  var i;

  if (options.version != null) {
    assert(utils.isNumber(options.version));
    this.version = options.version;
  }

  if (options.flag != null) {
    assert(utils.isNumber(options.flag));
    this.flag = options.flag;
  }

  if (options.inputs) {
    assert(Array.isArray(options.inputs));
    for (i = 0; i < options.inputs.length; i++)
      this.addInput(options.inputs[i]);
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    for (i = 0; i < options.outputs.length; i++)
      this.addOutput(options.outputs[i]);
  }

  if (options.locktime != null) {
    assert(utils.isNumber(options.locktime));
    this.locktime = options.locktime;
  }

  if (options.ps != null) {
    assert(utils.isNumber(options.ps));
    this.ps = options.ps;
  }

  if (options.changeIndex != null) {
    assert(utils.isNumber(options.changeIndex));
    this.changeIndex = options.changeIndex;
  }

  return this;
};

/**
 * Instantiate MTX from options.
 * @param {Object} options
 * @returns {MTX}
 */

MTX.fromOptions = function fromOptions(options) {
  return new MTX().fromOptions(options);
};

/**
 * Clone the transaction.
 * @returns {MTX}
 */

MTX.prototype.clone = function clone() {
  return new MTX(this);
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
  var input = new bcoin.input();
  input.mutable = true;

  if (options instanceof TX)
    input.fromTX(options, index);
  else if (options instanceof bcoin.coin)
    input.fromCoin(options);
  else
    input.fromOptions(options);

  this.inputs.push(input);

  return this;
};

/**
 * Add an output.
 * @example
 * tx.addOutput({ address: ..., value: 100000 });
 * tx.addOutput({ address: ..., value: utils.satoshi('0.1') });
 * tx.addOutput(receivingWallet, utils.satoshi('0.1'));
 * @param {Wallet|KeyRing|Object} obj - Wallet, Address,
 * or options (see {@link Script.createOutputScript} for options).
 * @param {Amount?} value - Only needs to be present for non-options.
 */

MTX.prototype.addOutput = function addOutput(options, value) {
  var output;

  if ((options instanceof bcoin.wallet)
      || (options instanceof bcoin.keyring)) {
    options = options.getAddress();
  }

  if (typeof options === 'string')
    options = bcoin.address.fromBase58(options);

  if (options instanceof bcoin.address)
    options = Script.fromAddress(options);

  output = new bcoin.output();
  output.mutable = true;

  if (options instanceof Script) {
    assert(utils.isNumber(value));
    assert(value >= 0);
    output.script.fromOptions(options);
    output.value = value;
  } else {
    output.fromOptions(options);
    assert(output.value >= 0);
  }

  this.outputs.push(output);

  return this;
};

/**
 * Build input script (or witness) templates (with
 * OP_0 in place of signatures).
 * @param {Number} index - Input index.
 * @param {KeyRing} ring - Address used to build. The address
 * must be able to redeem the coin.
 * @returns {Boolean} Whether the script was able to be built.
 * @throws on unavailable coins.
 */

function getRedeem(hash, script, program) {
  if (program) {
    if (utils.equal(program.hash160(), hash))
      return program;
  }

  if (script) {
    if (utils.equal(script.hash160(), hash))
      return script;

    if (utils.equal(script.sha256(), hash))
      return script;
  }
};


MTX.prototype.buildInput = function buildInput(index, key, script, program) {
  var input, prev, redeem;

  if (key.getPublicKey)
    key = key.getPublicKey();

  // Get the input
  input = this.inputs[index];
  assert(input);

  // We should have previous outputs by now.
  if (!input.coin)
    return false;

  // Don't bother with any below calculation
  // if the output is already templated.
  if (input.script.length !== 0 || input.witness.length !== 0)
    return true;

  // Get the previous output's script
  prev = input.coin.script;

  // This is easily the hardest part about building a transaction
  // with segwit: figuring out where the redeem script and witness
  // redeem scripts go.
  if (prev.isScripthash()) {
    redeem = getRedeem(prev.get(1), script, program);

    if (!redeem)
      return false;

    // Witness program nested in regular P2SH.
    if (redeem.isProgram()) {
      // P2WSH nested within pay-to-scripthash.
      if (redeem.isWitnessScripthash()) {
        prev = getRedeem(redeem.get(1), script, program);
        if (!prev)
          return false;
        this.scriptVector(prev, input.witness, key);
        input.witness.push(prev.toRaw());
        input.script.push(redeem.toRaw());
        input.script.compile();
        return true;
      }

      // P2WPKH nested within pay-to-scripthash.
      if (redeem.isWitnessPubkeyhash()) {
        prev = Script.fromPubkeyhash(utils.hash160(key));
        this.scriptVector(prev, input.witness, key);
        input.script.push(redeem.toRaw());
        input.script.compile();
        return true;
      }

      // Unknown witness program.
      return false;
    }

    // Regular P2SH.
    this.scriptVector(redeem, input.script, key);
    input.script.push(redeem.toRaw());
    input.script.compile();
    return true;
  }

  // Witness program.
  if (prev.isProgram()) {
    // Bare P2WSH.
    if (prev.isWitnessScripthash()) {
      redeem = getRedeem(prev.get(1), script, program);

      if (!redeem)
        return false;

      this.scriptVector(redeem, input.witness, key);
      input.witness.push(redeem.toRaw());
      input.script.compile();
      return true;
    }

    // Bare P2WPKH.
    if (prev.isWitnessPubkeyhash()) {
      prev = Script.fromPubkeyhash(prev.get(1));
      this.scriptVector(prev, input.witness, key);
      input.script.compile();
      return true;
    }

    // Bare... who knows?
    return false;
  }

  // Wow, a normal output! Praise be to Jengus and Gord.
  this.scriptVector(prev, input.script, key);
  return true;
};

MTX.prototype.scriptVector = function scriptVector(prev, vector, key) {
  var i, n;

  // P2PK
  if (prev.isPubkey()) {
    if (!utils.equal(prev.get(1), key))
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    vector.set(0, opcodes.OP_0);

    return true;
  }

  // P2PKH
  if (prev.isPubkeyhash()) {
    if (!utils.equal(prev.get(2), utils.hash160(key)))
      return false;

    // Already has a script template (at least)
    if (vector.length !== 0)
      return true;

    vector.set(0, opcodes.OP_0);
    vector.set(1, key);

    return true;
  }

  // Multisig
  if (prev.isMultisig()) {
    if (prev.indexOf(key) === -1)
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

    return true;
  }

  if (prev.indexOf(key) === -1)
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
};

/**
 * Sign an input.
 * @param {Number} index - Index of input being signed.
 * @param {KeyRing} ring - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 * @throws on unavailable coins.
 */

MTX.prototype.signInput = function signInput(index, key, type) {
  var input = this.inputs[index];
  var version = 0;
  var redeem = false;
  var prev, vector, sig, result;

  assert(input);

  if (key.getPrivateKey)
    key = key.getPrivateKey();

  // We should have previous outputs by now.
  if (!input.coin)
    return false;

  // Get the previous output's script
  prev = input.coin.script;
  vector = input.script;

  // Grab regular p2sh redeem script.
  if (prev.isScripthash()) {
    prev = input.script.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
    redeem = true;
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
    redeem = true;
    version = 1;
  } else if (prev.isWitnessPubkeyhash()) {
    prev = Script.fromPubkeyhash(prev.get(1));
    vector = input.witness;
    redeem = false;
    version = 1;
  }

  // Create our signature.
  sig = this.createSignature(index, prev, key, type, version);

  if (redeem) {
    redeem = vector.pop();
    result = this.signVector(prev, vector, sig, key);
    vector.push(redeem);
    vector.compile();
    return result;
  }

  return this.signVector(prev, vector, sig, key);
};

MTX.prototype.signVector = function signVector(prev, vector, sig, key) {
  var pub = bcoin.ec.publicKeyCreate(key, true);
  var keys, i, m, n, signatures, keyIndex;

  // P2PK
  if (prev.isPubkey()) {
    // Make sure the pubkey is ours.
    if (!utils.equal(pub, prev.get(0)))
      return false;

    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    if (vector.getSmall(0) !== 0)
      throw new Error('Input has not been templated.');

    vector.set(0, sig);
    vector.compile();

    return true;
  }

  // P2PKH
  if (prev.isPubkeyhash()) {
    // Make sure the pubkey hash is ours.
    if (!utils.equal(utils.hash160(pub), prev.get(2)))
      return false;

    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    if (!Script.isKey(vector.get(1)))
      throw new Error('Input has not been templated.');

    vector.set(0, sig);
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

  // Too many signature slots. Abort.
  if (vector.length - 1 > n)
    return false;

  // Count the number of current signatures.
  signatures = 0;
  for (i = 1; i < vector.length; i++) {
    if (Script.isSignature(vector.get(i)))
      signatures++;
  }

  // Signatures are already finalized.
  if (signatures === m && vector.length - 1 === m)
    return true;

  // Add some signature slots for us to use if
  // there was for some reason not enough.
  while (vector.length - 1 < n)
    vector.push(opcodes.OP_0);

  // Find the key index so we can place
  // the signature in the same index.
  keyIndex = utils.indexOf(keys, pub);

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
  if (keyIndex < vector.length && signatures < m) {
    if (vector.getSmall(keyIndex) === 0) {
      vector.set(keyIndex, sig);
      signatures++;
    }
  }

  // All signatures added. Finalize.
  if (signatures >= m) {
    // Remove empty slots left over.
    for (i = vector.length - 1; i >= 1; i--) {
      if (vector.getSmall(i) === 0)
        vector.remove(i);
    }

    // Remove signatures which are not required.
    // This should never happen.
    while (signatures > m) {
      vector.pop();
      signatures--;
    }

    // Sanity checks.
    assert(signatures === m);
    assert(vector.length - 1 === m);
  }

  vector.compile();

  return signatures === m;
};

MTX.prototype.combineMultisig = function combineMultisig(index, prev, version, script, signature) {
  var m = prev.getSmall(0);
  var sigs = [signature];
  var map = {};
  var result;
  var i, j, sig, type, msg, key, pub, res;

  for (i = 1; i < script.length; i++) {
    sig = script.get(i);
    if (Script.isSignature(sig))
      sigs.push(sig);
  }

  for (i = 0; i < sigs.length; i++) {
    sig = sigs[i];
    type = sig[sig.length - 1];

    msg = this.signatureHash(index, prev, type, version);

    for (j = 1; j < prev.length - 2; j++) {
      key = prev.get(j);
      pub = key.toString('hex');

      if (map[pub])
        continue;

      res = Script.checksig(msg, sig, key);

      if (res) {
        map[pub] = sig;
        if (utils.equal(sig, signature))
          result = true;
        break;
      }
    }
  }

  script.clear();
  script.push(opcodes.OP_0);
  for (i = 1; i < prev.length - 2; i++) {
    key = prev.get(i);
    pub = key.toString('hex');
    sig = map[pub];
    if (sig)
      script.push(sig);
  }

  while (script.length - 1 < m)
    script.push(opcodes.OP_0);

  script.compile();
  return result;
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

  if (type == null)
    type = constants.hashType.ALL;

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, prev, type, version);

  // Sign the transaction with our one input
  return Script.sign(hash, key, type);
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

    if (prev.isPubkey()) {
      if (!Script.isSignature(vector.get(0)))
        return false;
    } else if (prev.isPubkeyhash()) {
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
 * @param {KeyRing} ring - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 * @throws on unavailable coins.
 */

MTX.prototype.template = function template(key, script, program, type) {
  var total = 0;
  var i;

  if (key.getPublicKey)
    key = key.getPublicKey();

  for (i = 0; i < this.inputs.length; i++) {
    // Build script for input
    if (!this.buildInput(i, key, script, program))
      continue;
    total++;
  }

  return total;
};

/**
 * Built input scripts (or witnesses) and sign the inputs.
 * @param {Number} index - Index of input being signed.
 * @param {KeyRing} ring - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {HDPrivateKey|KeyPair|Buffer} key - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 * @throws on unavailable coins.
 */

MTX.prototype.sign = function sign(key, script, program, type) {
  var total = 0;
  var i, pub;

  if (key.getPrivateKey)
    key = key.getPrivateKey();

  pub = bcoin.ec.publicKeyCreate(key, true);

  for (i = 0; i < this.inputs.length; i++) {
    // Build script for input
    if (!this.buildInput(i, pub, script, program))
      continue;

    // Sign input
    if (!this.signInput(i, key, type))
      continue;

    total++;
  }

  return total;
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
    options = { wallet: options };

  if (options.wallet)
    wallet = options.wallet;

  function getRedeem(vector, hash) {
    var redeem = vector.getRedeem();
    var address;

    if (redeem)
      return redeem;

    if (!wallet)
      return;

    // Hack
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
    if (options.subtractFee || options.subtractFee === 0)
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
        : Script.fromPubkeyhash(constants.ZERO_HASH160),
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

MTX.prototype.fund = function fund(coins, options) {
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
    height = Math.max(0, height - (Math.random() * 100 | 0));

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
 * Mark inputs and outputs as mutable.
 * @private
 */

MTX.prototype._mutable = function _mutable() {
  var i;
  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].mutable = true;
  for (i = 0; i < this.outputs.length; i++)
    this.outputs[i].mutable = true;
  return this;
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
 * @see TX.fromExtended
 */

MTX.fromExtended = function fromExtended(data, saveCoins, enc) {
  if (typeof saveCoins === 'string') {
    enc = saveCoins;
    saveCoins = false;
  }

  if (typeof data === 'string')
    data = new Buffer(data, enc);

  return new MTX().fromExtended(data, saveCoins)._mutable();
};

/**
 * Convert the MTX to a TX.
 * @returns {TX}
 */

MTX.prototype.toTX = function toTX() {
  return new TX(this);
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
    && typeof obj.buildInput === 'function';
};

/*
 * Expose
 */

module.exports = MTX;

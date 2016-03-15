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
var Script = bcoin.script;

/**
 * TX
 */

function TX(data, block, index) {
  if (!(this instanceof TX))
    return new TX(data, block, index);

  if (!data)
    data = {};

  this.type = 'tx';
  this.version = data.version || 1;
  this.flag = data.flag || 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = data.locktime || 0;
  this.ts = data.ts || 0;
  this.block = data.block || null;
  this.index = data.index != null ? data.index : -1;
  this.ps = this.ts === 0 ? utils.now() : 0;

  this._hash = null;
  this._whash = null;
  this._raw = data._raw || null;
  this._size = data._size || 0;
  this._offset = data._offset || 0;
  this._witnessSize = data._witnessSize || 0;

  this.height = data.height != null ? data.height : -1;

  this._chain = data.chain;

  // assert(data.inputs.length !== 0);
  // assert(data.outputs.length !== 0);

  data.inputs.forEach(function(input) {
    this.inputs.push(new bcoin.input(input, this));
  }, this);

  data.outputs.forEach(function(output) {
    this.outputs.push(new bcoin.output(output, this));
  }, this);

  if (block && this.ts === 0) {
    if (block.type === 'merkleblock') {
      if (block.hasTX(this.hash('hex')))
        this.setBlock(block, index);
    } else {
      this.setBlock(block, index);
    }
  }
}

TX.prototype.setBlock = function setBlock(block, index) {
  this.ts = block.ts;
  this.block = block.hash('hex');
  this.height = block.height;
  this.index = index;
};

TX.prototype.hash = function hash(enc) {
  if (!this._hash)
    this._hash = utils.dsha256(this.renderNormal());

  return enc === 'hex' ? utils.toHex(this._hash) : this._hash;
};

TX.prototype.witnessHash = function witnessHash(enc) {
  if (this.isCoinbase()) {
    return enc === 'hex'
      ? utils.toHex(constants.zeroHash)
      : utils.slice(constants.zeroHash);
  }

  if (!this.hasWitness())
    return this.hash(enc);

  if (!this._whash)
    this._whash = utils.dsha256(this.renderWitness());

  return enc === 'hex' ? utils.toHex(this._whash) : this._whash;
};

TX.prototype.render = function render() {
  return this.getRaw();
};

TX.prototype.renderNormal = function renderNormal() {
  var raw = this.getRaw();
  if (!bcoin.protocol.parser.isWitnessTX(raw))
    return raw;
  return bcoin.protocol.framer.tx(this);
};

TX.prototype.renderWitness = function renderWitness() {
  var raw = this.getRaw();
  if (bcoin.protocol.parser.isWitnessTX(raw))
    return raw;
  return bcoin.protocol.framer.witnessTX(this);
};

TX.prototype.getRaw = function getRaw() {
  var raw;

  if (this._raw) {
    assert(this._size > 0);
    assert(this._witnessSize >= 0);
    return this._raw;
  }

  if (this.hasWitness())
    raw = bcoin.protocol.framer.witnessTX(this);
  else
    raw = bcoin.protocol.framer.tx(this);

  // this._raw = raw;
  this._size = raw.length;
  this._witnessSize = raw._witnessSize;

  return raw;
};

TX.prototype.getVirtualSize = function getVirtualSize() {
  var size, witnessSize, base;

  this.getRaw();

  size = this._size;
  witnessSize = this._witnessSize;
  base = size - witnessSize;

  return (base * 4 + witnessSize + 3) / 4 | 0;
};

TX.prototype.getSize = function getSize() {
  return this.getRaw().length;
};

TX.prototype.hasWitness = function hasWitness() {
  var i;

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].witness.items.length > 0)
      return true;
  }

  return false;
};

TX.prototype._inputIndex = function _inputIndex(hash, index) {
  var i, ex;

  for (i = 0; i < this.inputs.length; i++) {
    ex = this.inputs[i];
    if (ex.prevout.hash === hash && ex.prevout.index === index)
      return i;
  }

  return -1;
};

TX.prototype.signatureHash = function signatureHash(index, s, type, version) {
  assert(version >= 0 && version <= 1);
  if (version === 0)
    return this.signatureHashV0(index, s, type);
  if (version === 1)
    return this.signatureHashV1(index, s, type);
};

TX.prototype.signatureHashV0 = function signatureHashV0(index, s, type) {
  var i, msg, hash;

  var copy = {
    version: this.version,
    inputs: [],
    outputs: [],
    locktime: this.locktime
  };

  for (i = 0; i < this.inputs.length; i++) {
    copy.inputs.push({
      prevout: this.inputs[i].prevout,
      script: this.inputs[i].script.clone(),
      witness: this.inputs[i].witness.clone(),
      sequence: this.inputs[i].sequence
    });
  }

  for (i = 0; i < this.outputs.length; i++) {
    copy.outputs.push({
      value: this.outputs[i].value,
      script: this.outputs[i].script.clone()
    });
  }

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type];

  assert(index >= 0 && index < copy.inputs.length)
  assert(s instanceof bcoin.script);

  // Disable this for now. We allow null hash types
  // because bitcoind allows empty signatures. On
  // another note, we allow all weird sighash types
  // if strictenc is not enabled.
  // assert(utils.isFinite(type));

  // Remove all signatures.
  for (i = 0; i < copy.inputs.length; i++)
    copy.inputs[i].script = new Script([]);

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
      return utils.slice(constants.oneHash);

    // Drop all the outputs after the input index.
    copy.outputs.length = index + 1;

    // Null outputs that are not the at current input index.
    for (i = 0; i < copy.outputs.length; i++) {
      if (i !== index) {
        copy.outputs[i].script = new Script([]);
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

  copy = bcoin.protocol.framer.tx(copy);

  msg = new Buffer(copy.length + 4);
  utils.copy(copy, msg, 0);
  utils.writeU32(msg, type, copy.length);

  hash = utils.dsha256(msg);

  return hash;
};

TX.prototype.signatureHashV1 = function signatureHashV1(index, s, type) {
  var i, msg, hash, hashPrevouts, hashSequence, hashOutputs;
  var size, outputs, output, off, prev;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type];

  assert(index >= 0 && index < this.inputs.length)
  assert(s instanceof bcoin.script);

  if (!(type & constants.hashType.anyonecanpay)) {
    hashPrevouts = new Buffer(36 * this.inputs.length);
    off = 0;
    for (i = 0; i < this.inputs.length; i++) {
      prev = this.inputs[i].prevout;
      off += utils.copy(new Buffer(prev.hash, 'hex'), hashPrevouts, off);
      off += utils.writeU32(hashPrevouts, prev.index, off);
    }
    hashPrevouts = utils.dsha256(hashPrevouts);
  } else {
    hashPrevouts = new Buffer(32);
    hashPrevouts.fill(0);
  }

  if (!(type & constants.hashType.anyonecanpay)
      && (type & 0x1f) !== constants.hashType.single
      && (type & 0x1f) !== constants.hashType.none) {
    hashSequence = new Buffer(4 * this.inputs.length);
    off = 0;
    for (i = 0; i < this.inputs.length; i++)
      off += utils.writeU32(hashSequence, this.inputs[i].sequence, off);
    hashSequence = utils.dsha256(hashSequence);
  } else {
    hashSequence = new Buffer(32);
    hashSequence.fill(0);
  }

  if ((type & 0x1f) !== constants.hashType.single
      && (type & 0x1f) !== constants.hashType.none) {
    size = 0;
    outputs = [];
    for (i = 0; i < this.outputs.length; i++) {
      output = bcoin.protocol.framer.output(this.outputs[i]);
      size += output.length;
      outputs.push(output);
    }
    hashOutputs = new Buffer(size);
    off = 0;
    for (i = 0; i < outputs.length; i++)
      off += utils.copy(outputs[i], hashOutputs, off);
    hashOutputs = utils.dsha256(hashOutputs);
  } else if ((type & 0x1f) === constants.hashType.single && index < this.outputs.length) {
    hashOutputs = bcoin.protocol.framer.output(this.outputs[index]);
    hashOutputs = utils.dsha256(hashOutputs);
  } else {
    hashOutputs = new Buffer(32);
    hashOutputs.fill(0);
  }

  s = s.encode();

  msg = new Buffer(
    4 + 32 + 32 + 36
    + utils.sizeIntv(s.length)
    + s.length
    + 8 + 4 + 32 + 4 + 4);

  off = 0;
  off += utils.write32(msg, this.version, off);
  off += utils.copy(hashPrevouts, msg, off);
  off += utils.copy(hashSequence, msg, off);
  off += utils.copy(new Buffer(this.inputs[index].prevout.hash, 'hex'), msg, off);
  off += utils.writeU32(msg, this.inputs[index].prevout.index, off);
  assert(off === 4 + 32 + 32 + 36);
  off += utils.writeIntv(msg, s.length, off);
  off += utils.copy(s, msg, off);
  off += utils.write64(msg, this.inputs[index].output.value, off);
  off += utils.writeU32(msg, this.inputs[index].sequence, off);
  off += utils.copy(hashOutputs, msg, off);
  off += utils.writeU32(msg, this.locktime, off);
  assert(off === msg.length - 4);
  off += utils.writeU32(msg, type, off);
  assert(off === msg.length);

  hash = utils.dsha256(msg);

  return hash;
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

    return bcoin.script.verify(
      input.script,
      input.witness,
      input.output.script,
      this,
      i,
      flags
    );
  }, this);
};

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && +this.inputs[0].prevout.hash === 0;
};

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

TX.prototype.getInputAddresses = function getInputAddresses() {
  var table = {};
  var addresses = [];
  var i, address;

  for (i = 0; i < this.inputs.length; i++) {
    address = this.inputs[i].getAddress();
    if (address && !table[address]) {
      table[address] = true;
      addresses.push(address);
    }
  }

  addresses.table = table;

  return addresses;
};

TX.prototype.getOutputAddresses = function getOutputAddresses() {
  var table = {};
  var addresses = [];
  var i, address;

  for (i = 0; i < this.outputs.length; i++) {
    address = this.outputs[i].getAddress();
    if (address && !table[address]) {
      table[address] = true;
      addresses.push(address);
    }
  }

  addresses.table = table;

  return addresses;
};

TX.prototype.getAddresses = function getAddresses() {
  var input = this.getInputAddresses();
  var output = this.getOutputAddresses();
  var i;

  for (i = 0; i < output.length; i++) {
    if (!input.table[output[i]]) {
      input.table[output[i]] = true;
      input.push(output[i]);
    }
  }

  return input;
};

TX.prototype.testInputs = function testInputs(addressTable, index) {
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

    if (input.test(addressTable))
      return true;
  }

  return false;
};

TX.prototype.testOutputs = function testOutputs(addressTable, index) {
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

    if (output.test(addressTable))
      return true;
  }

  return false;
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

  if (txs instanceof TX) {
    txs = [txs];
    unspent = null;
  } else if (txs instanceof bcoin.coin) {
    unspent = [tx];
    txs = null;
  } else if (txs instanceof bcoin.txpool) {
    unspent = txs._unspent;
    txs = txs._all;
  } else if (txs instanceof bcoin.wallet && txs.tx) {
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

TX.prototype._getSigops = function _getSigops(scriptHash, accurate) {
  var total = 0;

  this.inputs.forEach(function(input) {
    var prev;

    if (!input.output)
      return;

    prev = input.output.script;

    total += input.script.getSigops(accurate);

    if (scriptHash && !this.isCoinbase()) {
      if (!prev.isScripthash())
        return;

      if (!input.script.isPushOnly())
        return;

      prev = input.script.getRedeem();

      total += prev.getSigops(true);
    }
  }, this);

  this.outputs.forEach(function(output) {
    total += output.script.getSigops(accurate);
  }, this);

  return total;
};

TX.prototype.getSigops = function getSigops(scriptHash, accurate) {
  var cost = this._getSigops(scriptHash, accurate) * 4;

  this.inputs.forEach(function(input) {
    var prev;

    if (!input.output)
      return;

    prev = input.output.script;

    if (prev.isScripthash())
      prev = input.script.getRedeem();

    if (prev.isWitnessScripthash()) {
      prev = input.witness.getRedeem();
      cost += prev.getSigops(true);
    } else {
      cost += 0;
    }
  }, this);

  this.outputs.forEach(function(output) {
    if (output.script.isWitnessPubkeyhash())
      cost += 1;
    else
      cost += 0;
  }, this);

  return (cost + 3) / 4 | 0;
};

TX.prototype.isStandard = function isStandard(flags) {
  var i, input, output, type;
  var nulldata = 0;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.version > constants.tx.version || this.version < 1)
    return false;

  if (this.getSize() > constants.tx.maxSize)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (input.script.getSize() > 1650)
      return false;

    // Not accurate?
    if (this.isCoinbase())
      continue;

    if (flags & constants.flags.VERIFY_SIGPUSHONLY) {
      if (!input.script.isPushOnly())
        return false;
    }
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    type = output.script.getType();

    if (!output.script.isStandard())
      return false;

    if (type === 'unknown')
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
  var i, input, args, stack, res, redeem, targs;
  var maxSigops = constants.script.maxScripthashSigops;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.output)
      return false;

    args = input.output.script.getArgs();

    if (args < 0)
      return false;

    stack = [];

    // Bitcoind doesn't do this, but it's possible someone
    // could DoS us by sending ridiculous txs to the mempool
    // if we don't put this here.
    if (!input.script.isPushOnly())
      return false;

    res = input.script.execute(stack, this, i, flags);

    // TODO: Segwit here.

    if (!res)
      return false;

    if ((flags & constants.flags.VERIFY_P2SH)
        && input.output.script.isScripthash()) {
      if (stack.length === 0)
        return false;

      redeem = bcoin.script.getRedeem(stack);

      if (!redeem)
        return false;

      // Not accurate?
      if (redeem.getSize() > 520)
        return false;

      // Also consider scripthash "unknown"?
      if (redeem.getType() === 'unknown') {
        if (redeem.getSigops(true) > maxSigops)
          return false;
        continue;
      }

      targs = redeem.getArgs();
      if (targs < 0)
        return false;
      args += targs;
    }

    if (stack.length !== args)
      return false;
  }

  return true;
};

TX.prototype.maxSize = function maxSize() {
  return this.getSize();
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
    if (this.inputs[i].getInputType() === type)
      return true;
  }
  for (var i = 0; i < this.outputs.length; i++) {
    if (this.outputs[i].getType() === type)
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
  return {
    type: this.type,
    hash: utils.revHex(this.hash('hex')),
    witnessHash: utils.revHex(this.witnessHash('hex')),
    height: this.height,
    value: utils.btc(this.getValue()),
    fee: utils.btc(this.getFee()),
    confirmations: this.getConfirmations(),
    priority: this.getPriority().toString(10),
    date: new Date(this.ts * 1000).toISOString(),
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    index: this.index,
    version: this.version,
    inputs: this.inputs,
    outputs: this.outputs,
    locktime: this.locktime
  };
};

TX.prototype.toJSON = function toJSON() {
  return {
    type: 'tx',
    hash: utils.revHex(this.hash('hex')),
    witnessHash: utils.revHex(this.witnessHash('hex')),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    changeIndex: this.changeIndex || -1,
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

TX._fromJSON = function fromJSON(json) {
  assert.equal(json.type, 'tx');
  return {
    block: json.block ? utils.revHex(json.block) : null,
    height: json.height,
    ts: json.ts,
    ps: json.ps,
    index: json.index,
    changeIndex: json.changeIndex || -1,
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

TX.fromJSON = function fromJSON(json) {
  assert.equal(json.type, 'tx');
  return new TX(TX._fromJSON(json));
};

TX.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

  if (enc === 'hex')
    data = utils.toHex(data);

  return data;
};

TX._fromRaw = function _fromRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseTX(data);
};

TX.fromRaw = function fromRaw(data, enc) {
  return new bcoin.tx(TX._fromRaw(data, enc));
};

TX.prototype.toExtended = function toExtended(saveCoins) {
  var height = this.height;
  var index = this.index;
  var changeIndex = this.changeIndex != null ? this.changeIndex : -1;
  var p = new bcoin.protocol.framer.BufferWriter();

  if (height === -1)
    height = 0x7fffffff;

  if (index === -1)
    index = 0x7fffffff;

  if (changeIndex === -1)
    changeIndex = 0x7fffffff;

  bcoin.protocol.framer.renderTX(this, true, p);
  p.writeU32(height);
  p.writeHash(this.block || constants.zeroHash);
  p.writeU32(this.index);
  p.writeU32(this.ts);
  p.writeU32(this.ps);
  // p.writeU32(changeIndex);

  if (saveCoins) {
    p.writeIntv(this.inputs.length);
    this.inputs.forEach(function(input) {
      if (!input.output) {
        p.writeVarBytes(new Buffer([]));
        return;
      }

      bcoin.protocol.framer.coin(input.output, false, p);
    });
  }

  return p.render();
};

TX._fromExtended = function _fromExtended(buf, saveCoins) {
  var p = new bcoin.protocol.parser.BufferReader(buf);
  var tx, coinCount, coin, i;

  p.start();

  tx = bcoin.protocol.parser.parseTX(p);

  tx.height = p.readU32();
  tx.block = p.readHash().toString('hex');
  tx.index = p.readU32();
  tx.ts = p.readU32();
  tx.ps = p.readU32();
  // tx.changeIndex = p.readU32();

  if (+tx.block === 0)
    tx.block = null;

  if (tx.height === 0x7fffffff)
    tx.height = -1;

  if (tx.index === 0x7fffffff)
    tx.index = -1;

  if (tx.changeIndex === 0x7fffffff)
    tx.changeIndex = -1;

  if (saveCoins) {
    coinCount = p.readUIntv();
    for (i = 0; i < coinCount; i++) {
      coin = p.readVarBytes();
      if (coin.length === 0)
        continue;
      coin = bcoin.protocol.parser.parseCoin(p, false);
      coin.hash = tx.inputs[i].prevout.hash;
      coin.index = tx.inputs[i].prevout.index;
      coin.spent = false;
      tx.inputs[i].output = coin;
    }
  }

  p.end();

  return tx;
};

TX.fromExtended = function fromExtended(buf, coins) {
  return new TX(TX._fromExtended(buf, coins));
};

/**
 * Expose
 */

module.exports = TX;

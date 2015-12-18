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
  this._network = data._network || false;
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

  if (!data.ts && block && block.hasTX(this.hash('hex'))) {
    this.ts = block.ts;
    this.block = block.hash('hex');
  }

  // ps = Pending Since
  this.ps = this.ts === 0 ? +new Date() / 1000 : 0;

  this.changeAddress = data.changeAddress || null;
}
module.exports = TX;

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
  if (this._network)
    return this._raw.slice();
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

  if (input.out.tx) {
    var prev = input.out.tx.outputs[input.out.index].script;
    var lock = bcoin.script.lockTime(prev);
    if (lock) {
      if (this._lock === 0)
        this.lock = Math.max(lock.toNumber(), this.lock);
      if (!bcoin.script.spendable(this, this.lock))
        throw new Error('Cannot spend ' + utils.revHex(input.out.hash));
    }
  }

  if (this.lock !== 0) {
    if (i.seq === undefined)
      input.seq = 0;
  }

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

TX.prototype.prevOut = function prevOut(i, def) {
  if (typeof i === 'object')
    i = this.inputs.indexOf(i);

  var input = this.inputs[i];

  if (!input || !input.out.tx || input.out.index == null)
    return def;

  return input.out.tx.outputs[input.out.index] || def;
};

TX.prototype.signatureHash = function signatureHash(i, type) {
  if (typeof i === 'object')
    i = this.inputs.indexOf(i);

  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the current input.
  var input = this.inputs[i];

  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(i, s, type);

  return hash;
};

TX.prototype.signature = function signature(i, key, type) {
  if (typeof i === 'object')
    i = this.inputs.indexOf(i);

  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.sigHash(i, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key.priv).toDER();

  // Add the sighash as a single byte to the signature
  signature = signature.concat(type);

  return signature;
};

// Build the scriptSigs for inputs, excluding the signatures
TX.prototype.scriptInput = function scriptInput(input, pub) {
  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

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
    var n = s[s.length - 2];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(n))
      n = n[0] || 0;
    for (var i = 0; i < n; i++)
      input.script[i + 1] = [];
    this._recalculateFee();
    return;
  }

  // P2SH multisig
  // p2sh format: OP_FALSE [sig-1] [sig-2] ... [redeem-script]
  if (bcoin.script.isScripthash(s)) {
    input.script = [ [] ];
    var redeem = bcoin.script.decode(pub);
    var n = redeem[redeem.length - 2];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(n))
      n = n[0] || 0;
    for (var i = 0; i < n; i++)
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
  if (!type)
    type = 'all';

  if (typeof type === 'string')
    type = constants.hashType[type];

  // Get the previous output's subscript
  var s = input.out.tx.getSubscript(input.out.index);

  // Get the hash of the current tx, minus the other inputs, plus the sighash.
  var hash = this.subscriptHash(this.inputs.indexOf(input), s, type);

  // Sign the transaction with our one input
  var signature = bcoin.ecdsa.sign(hash, key.priv).toDER();

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
    var len = input.script.length;
    var redeem;

    if (bcoin.script.isScripthash(s)) {
      len--;
      redeem = bcoin.script.decode(input.script[input.script.length - 1]);
    } else {
      redeem = s;
    }

    var m = redeem[0];
    // If using pushdata instead of OP_1-16:
    if (Array.isArray(m))
      m = m[0] || 0;

    var keys = redeem.slice(1, -2);
    var pub = key.getPublic(true, 'array');
    var pubn = key.getPublic(false, 'array');

    // Find the key index so we can place
    // the signature in the same index.
    for (var ki = 0; ki < keys.length; ki++) {
      if (utils.isEqual(pub, keys[ki]) || utils.isEqual(pubn, keys[ki]))
        break;
    }

    if (ki === keys.length)
      throw new Error('Public key is not in the prev_out script');

    if (ki + 1 > len - 1)
      throw new Error('No signature slot available');

    // Add our signature to the correct slot
    // and count the total number of signatures.
    var totalSigs = 0;
    for (var i = 1; i < len; i++) {
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
      for (var i = len - 1; i >= 1; i--) {
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

TX.prototype.output = function output(options, value) {
  if (options instanceof bcoin.wallet)
    options = options.getAddress();

  if (typeof options === 'string') {
    options = {
      address: options,
      value: value
    };
  }

  var output = {
    value: new bn(options.value),
    script: options.script ? options.script.slice() : []
  };

  this.outputs.push(output);

  this.scriptOutput(output, options);

  return this;
};

// compat
TX.prototype.out = TX.prototype.output;

TX.prototype.scriptOutput = function scriptOutput(output, options) {
  options = options || output;

  var script = output.script ? output.script.slice() : [];

  if (Array.isArray(options.keys || options.address)) {
    // Raw multisig transaction
    // https://github.com/bitcoin/bips/blob/master/bip-0010.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0019.mediawiki
    // [required-sigs] [pubkey-hash1] [pubkey-hash2] ... [number-of-keys] checkmultisig
    var keys = options.keys || options.address;

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
    var m = options.m || keys.length;
    var n = options.n || keys.length;

    assert(m >= 1 && m <= n);
    if (options.hash)
      assert(n >= 1 && n <= 15);
    else
      assert(n >= 1 && n <= 3);

    script = bcoin.script.multisig(keys, m, n);

    // make it p2sh
    if (options.scripthash) {
      var hash = utils.ripesha(bcoin.script.encode(script));
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
    var color = options.color;
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
  var output = this.outputs[index];
  assert(output);

  var script = output.script;
  return bcoin.script.subscript(script);
};

TX.prototype.subscriptHash = function subscriptHash(index, s, type) {
  var copy = this.clone();

  if (typeof type === 'string')
    type = constants.hashType[type];

  // bitcoind used to return 1 as an error code:
  // it ended up being treated like a hash.
  if (index >= copy.inputs.length)
    return constants.oneHash;

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
      return constants.oneHash;
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

  var verifyStr = copy.render();

  utils.writeU32(verifyStr, type, verifyStr.length);

  var hash = utils.dsha256(verifyStr);

  return hash;
};

TX.prototype.verify = function verify(index, force) {
  // Valid if included in block
  if (!force && this.ts !== 0)
    return true;

  if (this.inputs.length === 0)
    return false;

  return this.inputs.every(function(input, i) {
    if (index !== undefined && index !== i)
      return true;

    if (!input.out.tx)
      return false;

    assert(input.out.tx.outputs.length > input.out.index);

    var stack = [];
    var prev = input.out.tx.outputs[input.out.index].script;

    if (bcoin.script.isScripthash(prev)) {
      // p2sh transactions cannot have anything
      // other than pushdata ops in the scriptSig
      var push = input.script.slice(1).every(Array.isArray);
      if (!push)
        return false;
    }

    bcoin.script.execute(input.script, stack, this, i);
    var res = bcoin.script.execute(prev, stack, this, i);
    if (!res)
      return false;

    // Might be necessary for arithmetic:
    // if (stack.length === 0 || new bn(stack.pop()).cmp(0) !== 0)

    if (stack.length === 0 || !utils.isEqual(stack.pop(), [ 1 ]))
      return false;

    if (bcoin.script.isScripthash(prev)) {
      var redeem = input.script[input.script.length - 1];
      if (!Array.isArray(redeem))
        return false;
      redeem = bcoin.script.decode(redeem);
      res = bcoin.script.execute(redeem, stack, this, i);
      if (!res)
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
  copy.inputs.forEach(function(input) {
    input.script = [];
  });

  var size = copy.render().length;

  // Add size for signatures and public keys
  copy.inputs.forEach(function(input, i) {
    // Get the previous output's script
    // var s = input.out.tx.outputs[input.out.index].script;

    // Get the previous output's subscript
    var s = input.out.tx.getSubscript(input.out.index);

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
      var m = s[0];
      // If using pushdata instead of OP_1-16:
      if (Array.isArray(m))
        m = m[0] || 0;
      assert(m >= 1 && m <= 3);
      size += 74 * m;
      return;
    }

    if (bcoin.script.isScripthash(s)) {
      var script = this.inputs[i].script;
      var redeem, m, n;
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

// Building a TX:
// 1. Add outputs:
//   - this.output({ address: ..., value: ... });
//   - this.output({ address: ..., value: ... });
// 2. Add inputs with utxos and change output:
//   - this.fillUnspent(unspentItems, [changeAddr]);
// 3. Fill input scripts (for each input):
//   - this.scriptInput(input, pub)
//   - this.signInput(input, key, [sigHashType])
TX.prototype.utxos = function utxos(unspent) {
  // NOTE: tx should be prefilled with all outputs
  var cost = this.funds('out');

  // Use initial fee for starters
  var fee = 1;

  // total = cost + fee
  var total = cost.add(new bn(TX.fee));

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

  // Add dummy output (for `change`) to calculate maximum TX size
  this.output({ address: null, value: new bn(0) });

  // Change fee value if it is more than 1024 bytes
  // (10000 satoshi for every 1024 bytes)
  do {
    // Calculate maximum possible size after signing
    var byteSize = this.maxSize();

    var addFee = Math.ceil(byteSize / 1024) - fee;
    total.iadd(new bn(addFee * TX.fee));
    fee += addFee;

    // Failed to get enough funds, add more inputs
    if (this.funds('in').cmp(total) < 0)
      unspent.slice(lastAdded).every(addInput, this);
  } while (this.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

  // Still failing to get enough funds
  if (this.funds('in').cmp(total) < 0) {
    this.inputs = inputs;
    this.outputs.pop();
    return null;
  }

  // How much money is left after sending outputs
  var change = this.funds('in').sub(total);

  // Clear the tx of everything we added.
  this.inputs = inputs;
  this.outputs.pop();

  // Return necessary utxos and change.
  return {
    utxos: utxos,
    change: change,
    cost: cost,
    fee: total.sub(cost),
    total: total
  };
};

TX.prototype.fillUnspent = function fillUnspent(unspent, changeAddress) {
  var result = unspent.utxos ? unspent : this.utxos(unspent);

  this.filled = result;

  this.changeAddress = changeAddress || this.changeAddress;

  if (!result)
    return result;

  result.utxos.forEach(function(utxo) {
    this.input(utxo, null);
  }, this);

  if (result.change.cmpn(TX.dust) < 0) {
    // Do nothing. Change is added to fee.
    assert(this.getFee().cmp(result.fee.add(result.change)) === 0);
    // Adding change to outputs.
    // this.outputs[this.outputs.length - 1].value.iadd(result.change);
    this.changeOutput = null;
  } else {
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

TX.prototype.inputAddrs = function inputAddrs() {
  return this.inputs.filter(function(input) {
    return bcoin.script.isPubkeyhashInput(input.script);
  }).map(function(input) {
    var pub = input.script[1];
    var hash = utils.ripesha(pub);
    return bcoin.wallet.hash2addr(hash, 'pubkeyhash');
  });
};

TX.getInputData = function getInputData(input) {
  if (!input || !input.script) return;

  var script = input.script;

  if (bcoin.script.isPubkeyhashInput(script)) {
    var scriptSig = utils.toHex(script[0]);
    var pubKey = script[1];
    var hash = utils.ripesha(pubKey);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      sig: scriptSig,
      pub: pubKey,
      hash: hash,
      addr: addr
    };
  }

  if (bcoin.script.isScripthashInput(script)) {
    var pub = script[script.length - 1];
    var hash = utils.ripesha(pub);
    var addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    var redeem = bcoin.script.decode(pub);
    var data = TX.getOutputData({ script: redeem });
    data.pub = pub;
    data.hash = hash;
    data.addr = addr;
    data.scripthash = {
      redeem: redeem,
      pub: pub,
      hash: hash,
      addr: addr,
      m: data.multisig.m,
      n: data.multisig.n,
      keys: data.multisig.keys,
      hashes: data.multisig.hashes,
      addrs: data.multisig.addrs
    };
    return data;
  }

  if (!input.out.tx)
    return;

  var output = input.out.tx.outputs[input.out.index];

  return TX.getOutputData(output);
};

TX.getOutputData = function getOutputData(output) {
  if (!output || !output.script) return;

  var script = output.script;

  if (bcoin.script.isPubkey(script)) {
    var pubKey = script[0];
    var hash = utils.ripesha(pubKey);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      sig: null,
      pub: pubKey,
      hash: hash,
      addr: addr
    };
  }

  if (bcoin.script.isPubkeyhash(script)) {
    var hash = script[2];
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      sig: null,
      pub: null,
      hash: hash,
      addr: addr
    };
  }

  var pubs = bcoin.script.isMultisig(script);
  if (pubs) {
    var hash = utils.ripesha(pubs[0]);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      sig: null,
      pub: pubs[0],
      hash: hash,
      addr: addr,
      keys: pubs,
      multisig: {
        m: new bn(script[0]).toNumber(),
        n: new bn(script[script.length - 2]).toNumber(),
        keys: keys,
        hashes: keys.map(function(key) {
          return utils.ripesha(key);
        }),
        addrs: keys.map(function(key) {
          var hash = utils.ripesha(key);
          return bcoin.wallet.hash2addr(hash);
        })
      }
    };
  }

  if (bcoin.script.isScripthash(script)) {
    var hash = utils.toHex(s[1]);
    var addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    return {
      sig: null,
      pub: null,
      hash: hash,
      addr: addr,
      scripthash: {
        redeem: null,
        pub: null,
        hash: hash,
        addr: addr
      }
    };
  }

  if (bcoin.script.isColored(script)) {
    return {
      data: bcoin.script.colored(script)
    };
  }
};

TX.prototype.getFee = function getFee() {
  return this.funds('in').sub(this.funds('out'));
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

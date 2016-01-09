/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

/**
 * Input
 */

function Input(options) {
  var tx = options.tx;
  var lock;

  if (!(this instanceof Input))
    return new Input(options);

  if (!tx)
    throw new Error('No TX passed into Input.');

  this.out = {
    tx: options.out.tx || null,
    hash: options.out.hash || null,
    index: options.out.index
  };

  this.script = options.script ? options.script.slice() : [];
  this.seq = options.seq === undefined ? 0xffffffff : options.seq;

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);

  if (this.output) {
    lock = this.lock;
    if (lock > 0) {
      if (tx._lock === 0)
        tx.lock = Math.max(lock, tx.lock);
      if (!bcoin.script.spendable(this.output.script, tx.lock))
        throw new Error('Cannot spend ' + utils.revHex(this.out.hash));
    }
  }

  if (tx.lock !== 0) {
    if (options.seq === undefined)
      this.seq = 0;
  }
}

Input.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Input.getData(this);

  if (this.script.length && this.out.tx)
    utils.hidden(this, '_data', data);

  return data;
});

Input.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Input.prototype.__defineGetter__('signature', function() {
  return this.signatures[0];
});

Input.prototype.__defineGetter__('key', function() {
  return this.data.redeem || this.keys[0];
});

Input.prototype.__defineGetter__('hash', function() {
  return this.data.scripthash || this.hashes[0];
});

Input.prototype.__defineGetter__('address', function() {
  return this.data.scriptaddress || this.addresses[0] || this._id;
});

Input.prototype.__defineGetter__('signatures', function() {
  return this.data.signatures || [];
});

Input.prototype.__defineGetter__('keys', function() {
  return this.data.keys || [];
});

Input.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes || [];
});

Input.prototype.__defineGetter__('addresses', function() {
  return this.data.addresses || [];
});

Input.prototype.__defineGetter__('scriptaddress', function() {
  return this.data.scriptaddress;
});

Input.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Input.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Input.prototype.__defineGetter__('lock', function() {
  if (!this.output)
    return 0;
  return this.output.lock || 0;
});

Input.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

Input.prototype.__defineGetter__('output', function() {
  if (!this.out.tx)
    return;
  return this.out.tx.outputs[this.out.index];
});

Input.prototype.__defineGetter__('value', function() {
  if (!this.output)
    return new bn(0);
  return this.output.value;
});

Input.prototype.__defineGetter__('tx', function() {
  return this.out.tx;
});

Input.prototype.__defineGetter__('_id', function() {
  var data = [].concat(
    this.out.hash,
    this.out.index,
    bcoin.script.encode(this.script),
    this.seq
  );
  var hash = utils.toHex(utils.dsha256(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
});

Input.prototype.__defineGetter__('addr', function() {
  return this.address;
});

Input.prototype.__defineGetter__('addrs', function() {
  return this.addresses;
});

Input.prototype.__defineGetter__('pub', function() {
  return this.key;
});

Input.prototype.__defineGetter__('pubs', function() {
  return this.keys;
});

Input.prototype.__defineGetter__('sig', function() {
  return this.signature;
});

Input.prototype.__defineGetter__('sigs', function() {
  return this.signatures;
});

Input.prototype.__defineGetter__('scriptaddr', function() {
  return this.scriptaddress;
});

// Schema and defaults for data object:
// {
//   type: null,
//   side: 'input',
//   signatures: [],
//   keys: [],
//   hashes: [],
//   addresses: [],
//   redeem: null,
//   scripthash: null,
//   scriptaddress: null,
//   m: 0,
//   n: 0,
//   height: -1,
//   flags: null,
//   text: null,
//   lock: 0,
//   value: new bn(0),
//   script: s,
//   seq: input.seq,
//   prev: null,
//   index: null,
//   _script: null,
//   none: false
// }

Input.getData = function getData(input) {
  var s, sub, def, signature, key, hash, address, redeem, data, output, val;

  if (Array.isArray(input)) {
    input = {
      out: {
        tx: null,
        hash: utils.toHex(constants.oneHash),
        index: 0
      },
      script: input,
      seq: 0xffffffff
    };
  }

  if (!input || !input.script)
    return;

  s = input.script;
  sub = bcoin.script.subscript(input.script);

  def = {
    side: 'input',
    value: new bn(0),
    script: s,
    seq: input.seq
  };

  if (bcoin.script.lockTime(sub))
    sub = sub.slice(3);

  if (input.out) {
    def.prev = input.out.hash;
    def.index = input.out.index;
  }

  if (input.out && +input.out.hash === 0) {
    data = bcoin.script.coinbase(input.script);
    return utils.merge(def, {
      type: 'coinbase',
      height: data.height != null ? data.height : -1,
      flags: data.flags,
      text: data.text,
      none: true
    });
  }

  if (input.out && input.out.tx) {
    output = input.out.tx.outputs[input.out.index];
    data = bcoin.output.getData(output);
    if (data.type === 'pubkey' ) {
      data.signatures = [sub[0]];
    } else if (data.type === 'pubkeyhash') {
      data.signatures = [sub[0]];
      data.keys = [sub[1]];
    } else if (data.type === 'multisig') {
      data.signatures = sub.slice(1);
    } else if (data.type === 'scripthash') {
      // We work backwards here: scripthash is one of the few cases
      // where we get more data from the input than the output.
      val = Input.getData({
        out: { hash: input.out.hash, index: input.out.index },
        script: input.script,
        seq: input.seq
      });
      val.lock = data.lock;
      val.value = data.value;
      val.script = data.script;
      data = val;
    }
    return utils.merge(data, {
      seq: def.seq,
      prev: def.prev,
      index: def.index,
      _script: def.script
    });
  }

  if (bcoin.script.isPubkeyInput(s)) {
    return utils.merge(def, {
      type: 'pubkey',
      signatures: [sub[0]],
      none: true
    });
  }

  if (bcoin.script.isPubkeyhashInput(s)) {
    key = sub[1];
    hash = utils.ripesha(key);
    address = bcoin.wallet.hash2addr(hash);
    return utils.merge(def, {
      type: 'pubkeyhash',
      signatures: [sub[0]],
      keys: [key],
      hashes: [hash],
      addresses: [address]
    });
  }

  if (bcoin.script.isMultisigInput(s)) {
    signature = sub.slice(1);
    return utils.merge(def, {
      type: 'multisig',
      signatures: signature,
      m: signature.length,
      none: true
    });
  }

  if (bcoin.script.isScripthashInput(s)) {
    signature = sub.slice(1, -1);
    redeem = sub[sub.length - 1];
    hash = utils.ripesha(redeem);
    address = bcoin.wallet.hash2addr(hash, 'scripthash');
    redeem = bcoin.script.decode(redeem);
    data = bcoin.output.getData({
      script: redeem,
      value: new bn(0)
    });
    return utils.merge(data, {
      type: 'scripthash',
      side: 'input',
      signatures: signature,
      redeem: redeem,
      scripthash: hash,
      scriptaddress: address,
      script: s,
      seq: input.seq
    });
  }

  return utils.merge(def, {
    type: 'unknown',
    none: true
  });
};

Input.prototype.inspect = function inspect() {
  var output = this.output
    ? this.output.inspect()
    : { type: 'unknown', value: '0.0' };

  output.hash = this.out.hash;
  output.rhash = utils.revHex(this.out.hash);
  output.index = this.out.index;

  return {
    type: this.type,
    address: this.address,
    signatures: this.signatures.map(utils.toHex),
    keys: this.keys.map(utils.toHex),
    text: this.text,
    lock: this.lock,
    value: utils.btc(output.value),
    script: bcoin.script.format(this.script)[0],
    seq: this.seq,
    output: output
  };
};

/**
 * Expose
 */

module.exports = Input;

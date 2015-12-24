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

Input.prototype.__defineGetter__('sig', function() {
  return this.data.sigs[0];
});

Input.prototype.__defineGetter__('pub', function() {
  return this.data.pubs[0];
});

Input.prototype.__defineGetter__('hash', function() {
  return this.data.hashes[0];
});

Input.prototype.__defineGetter__('addr', function() {
  return this.data.scriptaddr
    || this.data.addrs[0]
    || this._id(this.type);
});

Input.prototype.__defineGetter__('sigs', function() {
  return this.data.sigs;
});

Input.prototype.__defineGetter__('pubs', function() {
  return this.data.pubs;
});

Input.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes;
});

Input.prototype.__defineGetter__('addrs', function() {
  return this.data.addrs;
});

Input.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Input.prototype.__defineGetter__('n', function() {
  return this.data.n || this.data.m || 1;
});

Input.prototype.__defineGetter__('lock', function() {
  if (!this.output)
    return 0;
  return this.output.lock;
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

Input.prototype._id = function _id(prefix) {
  var data = [].concat(
    this.out.hash,
    this.out.index,
    bcoin.script.encode(this.script),
    this.seq
  );
  var hash = utils.toHex(utils.dsha256(data));
  return '[' + prefix + ':' + hash.slice(0, 7) + ']';
};

Input.getData = function getData(input) {
  if (!input || !input.script)
    return;

  var s = input.script;
  var sub = bcoin.script.subscript(input.script);
  var schema, sig, pub, hash, addr, redeem, data, output, val;

  schema = {
    type: null,
    side: 'input',
    sigs: [],
    pubs: [],
    hashes: [],
    addrs: [],
    redeem: null,
    scripthash: null,
    scriptaddr: null,
    m: 0,
    n: 0,
    height: -1,
    flags: null,
    text: null,
    lock: 0,
    value: new bn(0),
    script: s,
    seq: input.seq,
    tx: null,
    index: null,
    _script: null,
    none: false
  };

  if (bcoin.script.lockTime(sub))
    sub = sub.slice(3);

  if (input.out && +input.out.hash === 0) {
    data = bcoin.script.coinbase(input.script);
    return utils.merge(schema, {
      type: 'coinbase',
      height: data.height != null ? data.height : -1,
      flags: data.flags,
      text: data.text.join('').replace(/[\r\n\t\v]/g, ''),
      none: true
    });
  }

  if (input.out && input.out.tx) {
    output = input.out.tx.outputs[input.out.index];
    data = bcoin.output.getData(output);
    if (data.type === 'pubkey' ) {
      data.sigs = [sub[0]];
    } else if (data.type === 'pubkeyhash') {
      data.sigs = [sub[0]];
      data.pubs = [sub[1]];
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
    } else if (data.type === 'multisig') {
      data.sigs = sub.slice(1);
    }
    return utils.merge(data, {
      seq: input.seq,
      tx: input.out.hash,
      index: input.out.index,
      _script: s
    });
  }

  if (bcoin.script.isPubkeyInput(s)) {
    return utils.merge(schema, {
      type: 'pubkey',
      sigs: [sub[0]],
      none: true
    });
  }

  if (bcoin.script.isPubkeyhashInput(s)) {
    pub = sub[1];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'pubkeyhash',
      sigs: [sub[0]],
      pubs: [pub],
      hashes: [hash],
      addrs: [addr]
    });
  }

  if (bcoin.script.isScripthashInput(s)) {
    sig = sub.slice(1, -1);
    redeem = sub[sub.length - 1];
    hash = utils.ripesha(redeem);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    redeem = bcoin.script.decode(redeem);
    data = bcoin.output.getData({
      script: redeem,
      value: new bn(0)
    });
    return utils.merge(data, {
      type: 'scripthash',
      side: 'input',
      sigs: sig,
      redeem: redeem,
      scripthash: hash,
      scriptaddr: addr,
      script: s,
      seq: input.seq
    });
  }

  if (bcoin.script.isMultisigInput(s)) {
    sig = sub.slice(1);
    return utils.merge(schema, {
      type: 'multisig',
      sigs: sig,
      m: sig.length,
      none: true
    });
  }

  return utils.merge(schema, {
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
    addr: this.addr,
    sigs: this.sigs.map(utils.toHex),
    pubs: this.pubs.map(utils.toHex),
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

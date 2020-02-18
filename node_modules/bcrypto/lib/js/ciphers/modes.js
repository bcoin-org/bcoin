/*!
 * modes.js - cipher modes for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const gcm = require('./gcm');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const ZERO16 = Buffer.alloc(16, 0x00);

/**
 * Cipher
 */

class Cipher {
  constructor(ctx, padding = false) {
    assert(ctx && typeof ctx.encrypt === 'function');
    assert(typeof ctx.blockSize === 'number');
    assert(typeof padding === 'boolean');

    this.ctx = ctx;
    this.padding = padding;
    this.block = Buffer.allocUnsafe(ctx.blockSize);
    this.bpos = -1;
    this.last = EMPTY;
  }

  get blockSize() {
    return this.block.length;
  }

  init(key, iv) {
    if (iv == null)
      iv = EMPTY;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(iv));

    this.ctx.init(key);
    this.bpos = 0;
    this.last = EMPTY;
    this._init(key, iv);

    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    if (this.bpos === -1)
      throw new Error('Cipher not initialized.');

    const bs = this.block.length;

    let bpos = this.bpos;
    let ilen = input.length;
    let olen = ilen - (ilen % bs);
    let ipos = 0;
    let opos = 0;

    this.bpos = (this.bpos + ilen) % bs;

    if (bpos > 0) {
      let want = bs - bpos;

      if (want > ilen)
        want = ilen;

      input.copy(this.block, bpos, ipos, ipos + want);

      bpos += want;
      ilen -= want;
      ipos += want;

      if (bpos < bs)
        return EMPTY;

      olen += bs;
    }

    const output = Buffer.allocUnsafe(olen);

    if (ipos) {
      this._update(this.block, 0, output, opos);
      opos += bs;
    }

    while (ilen >= bs) {
      this._update(input, ipos, output, opos);
      opos += bs;
      ipos += bs;
      ilen -= bs;
    }

    if (ilen > 0)
      input.copy(this.block, 0, ipos, ipos + ilen);

    if (!this.padding)
      return output;

    this.last = output;

    return output.slice(0, olen - bs);
  }

  final() {
    if (this.bpos === -1)
      throw new Error('Cipher not initialized.');

    let ret;
    try {
      ret = this._final();
    } finally {
      this.ctx.destroy();
      this.block.fill(0x00);
      this.bpos = -1;
      this.last = EMPTY;
    }

    return ret;
  }

  setAAD(data) {
    throw new Error('Not authenticated.');
  }

  getAuthTag() {
    throw new Error('Not authenticated.');
  }

  setAuthTag(tag) {
    throw new Error('Not authenticated.');
  }

  _init() {
    return this;
  }

  _update() {
    throw new Error('Unimplemented.');
  }

  _final() {
    return EMPTY;
  }
}

/**
 * Block Cipher
 * @extends Cipher
 */

class BlockCipher extends Cipher {
  constructor(ctx, chain = false) {
    assert(typeof chain === 'boolean');

    super(ctx, false);

    this.chain = chain;
    this.prev = EMPTY;
    this.ppos = 0;
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));

    if (this.chain)
      assert(iv.length === this.blockSize);
    else
      assert(iv.length === 0);

    this.prev = iv;
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      const bs = this.blockSize;

      for (let i = 0; i < bs; i++)
        output[opos + i] = input[ipos + i] ^ this.prev[this.ppos + i];

      this.ctx.encrypt(output, opos, output, opos);

      this.prev = output;
      this.ppos = opos;
    } else {
      this.ctx.encrypt(input, ipos, output, opos);
    }

    return this;
  }

  _final() {
    const bs = this.blockSize;
    const left = bs - this.bpos;
    const block = Buffer.from(this.block);

    block.fill(left, this.bpos, bs);

    this._update(block, 0, block, 0);

    this.prev = EMPTY;
    this.ppos = 0;

    return block;
  }
}

/**
 * Block Decipher
 * @extends Cipher
 */

class BlockDecipher extends Cipher {
  constructor(ctx, chain = false) {
    assert(typeof chain === 'boolean');

    super(ctx, true);

    this.chain = chain;
    this.prev = EMPTY;
    this.ppos = 0;
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));

    if (this.chain)
      assert(iv.length === this.blockSize);
    else
      assert(iv.length === 0);

    this.prev = iv;
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      const bs = this.blockSize;

      this.ctx.decrypt(input, ipos, output, opos);

      for (let i = 0; i < bs; i++)
        output[opos + i] = output[opos + i] ^ this.prev[this.ppos + i];

      this.prev = input;
      this.ppos = ipos;
    } else {
      this.ctx.decrypt(input, ipos, output, opos);
    }

    return this;
  }

  _final() {
    const bs = this.blockSize;
    const block = this.last;

    this.prev = EMPTY;
    this.ppos = 0;

    if (block.length === 0)
      throw new Error('Bad decrypt (no data).');

    if (this.bpos !== 0)
      throw new Error('Bad decrypt (trailing bytes).');

    const left = block[block.length - 1];

    if (left === 0 || left > bs)
      throw new Error('Bad decrypt (padding).');

    assert(block.length >= bs);

    const start = block.length - bs;
    const end = block.length - left;

    for (let i = end; i < block.length; i++) {
      if (block[i] !== left)
        throw new Error('Bad decrypt (padding).');
    }

    return block.slice(start, end);
  }
}

/**
 * ECB Cipher
 * @extends BlockCipher
 */

class ECBCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * ECB Decipher
 * @extends BlockDecipher
 */

class ECBDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * CBC Cipher
 * @extends BlockCipher
 */

class CBCCipher extends BlockCipher {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CBC Decipher
 * @extends BlockDecipher
 */

class CBCDecipher extends BlockDecipher {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CTR
 * @extends Cipher
 */

class CTR extends Cipher {
  constructor(ctx) {
    super(ctx, false);

    this.state = EMPTY;
    this.ctr = EMPTY;
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    this.state = Buffer.allocUnsafe(this.blockSize);
    this.ctr = Buffer.from(iv);

    return this;
  }

  _increment() {
    for (let i = this.ctr.length - 1; i >= 0; i--) {
      if (this.ctr[i] !== 0xff) {
        this.ctr[i] += 1;
        break;
      }

      this.ctr[i] = 0x00;
    }
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.ctr, 0, this.state, 0);
    this._increment();

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];

    return this;
  }

  _final() {
    this.ctx.encrypt(this.ctr, 0, this.state, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.state[i];

    this.state.fill(0x00);
    this.ctr.fill(0x00);
    this.state = EMPTY;
    this.ctr = EMPTY;

    return out;
  }
}

/**
 * CTR Cipher
 * @extends CTR
 */

class CTRCipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CTR Decipher
 * @extends CTR
 */

class CTRDecipher extends CTR {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * CFB
 * @extends Cipher
 */

class CFB extends Cipher {
  constructor(ctx, encrypt = true) {
    assert(typeof encrypt === 'boolean');

    super(ctx, false);

    this.encrypt = encrypt;
    this.state = EMPTY;
    this.prev = EMPTY;
    this.ppos = 0;
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    this.state = Buffer.allocUnsafe(this.blockSize);
    this.prev = iv;
    this.ppos = 0;

    return this;
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.prev, this.ppos, this.state, 0);

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];

    if (this.encrypt) {
      this.prev = output;
      this.ppos = opos;
    } else {
      this.prev = input;
      this.ppos = ipos;
    }

    return this;
  }

  _final() {
    this.ctx.encrypt(this.prev, this.ppos, this.state, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.state[i];

    this.state.fill(0x00);
    this.state = EMPTY;
    this.prev = EMPTY;
    this.ppos = 0;

    return out;
  }
}

/**
 * CFB Cipher
 * @extends CFB
 */

class CFBCipher extends CFB {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * CFB Decipher
 * @extends CFB
 */

class CFBDecipher extends CFB {
  constructor(ctx) {
    super(ctx, false);
  }
}

/**
 * OFB
 * @extends Cipher
 */

class OFB extends Cipher {
  constructor(ctx) {
    super(ctx, false);

    this.state = EMPTY;
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    this.state = Buffer.from(iv);

    return this;
  }

  _update(input, ipos, output, opos) {
    const bs = this.blockSize;

    this.ctx.encrypt(this.state, 0, this.state, 0);

    for (let i = 0; i < bs; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];

    return this;
  }

  _final() {
    this.ctx.encrypt(this.state, 0, this.state, 0);

    const out = Buffer.allocUnsafe(this.bpos);

    for (let i = 0; i < this.bpos; i++)
      out[i] = this.block[i] ^ this.state[i];

    this.state.fill(0x00);
    this.state = EMPTY;

    return out;
  }
}

/**
 * OFB Cipher
 * @extends OFB
 */

class OFBCipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * OFB Decipher
 * @extends OFB
 */

class OFBDecipher extends OFB {
  constructor(ctx) {
    super(ctx);
  }
}

/**
 * GCM
 * @extends Cipher
 */

class GCM {
  constructor(ctx, encrypt) {
    this.aead = new gcm.GCM(ctx);
    this.encrypt = encrypt;
    this.tag = ZERO16;
    this.mac = ZERO16;
  }

  get blockSize() {
    return 16;
  }

  init(key, iv) {
    this.aead.init(key, iv);
    this.tag = ZERO16;
    this.mac = ZERO16;
    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    const out = Buffer.allocUnsafe(input.length);
    input.copy(out, 0);

    if (this.encrypt)
      this.aead.encrypt(out);
    else
      this.aead.decrypt(out);

    return out;
  }

  final() {
    this.mac = this.aead.final(this.tag.length);

    if (!this.encrypt) {
      if (!gcm.GCM.verify(this.tag, this.mac))
        throw new Error('Invalid decryption tag.');
    }

    return EMPTY;
  }

  setAAD(data) {
    this.aead.aad(data);
    return this;
  }

  getAuthTag() {
    assert(this.encrypt);
    return this.mac;
  }

  setAuthTag(tag) {
    assert(!this.encrypt);
    assert(Buffer.isBuffer(tag));
    const t = tag.length;
    assert(t === 4 || t === 8 || (t >= 12 && t <= 16));
    this.tag = tag;
    return this;
  }
}

/**
 * GCM Cipher
 * @extends GCM
 */

class GCMCipher extends GCM {
  constructor(ctx) {
    super(ctx, true);
  }
}

/**
 * GCM Decipher
 * @extends GCM
 */

class GCMDecipher extends GCM {
  constructor(ctx) {
    super(ctx, false);
  }
}

/*
 * Helpers
 */

function get(name, encrypt = true) {
  assert(typeof name === 'string');
  assert(typeof encrypt === 'boolean');

  switch (name) {
    case 'ECB':
      return encrypt ? ECBCipher : ECBDecipher;
    case 'CBC':
      return encrypt ? CBCCipher : CBCDecipher;
    case 'CTR':
      return encrypt ? CTRCipher : CTRDecipher;
    case 'CFB':
      return encrypt ? CFBCipher : CFBDecipher;
    case 'OFB':
      return encrypt ? OFBCipher : OFBDecipher;
    case 'GCM':
      return encrypt ? GCMCipher : GCMDecipher;
    default:
      throw new Error(`Unknown mode: ${name}.`);
  }
}

/*
 * Expose
 */

exports.Cipher = Cipher;
exports.BlockCipher = BlockCipher;
exports.BlockDecipher = BlockDecipher;
exports.ECBCipher = ECBCipher;
exports.ECBDecipher = ECBDecipher;
exports.CBCCipher = CBCCipher;
exports.CBCDecipher = CBCDecipher;
exports.CTR = CTR;
exports.CTRCipher = CTRCipher;
exports.CTRDecipher = CTRDecipher;
exports.CFB = CFB;
exports.CFBCipher = CFBCipher;
exports.CFBDecipher = CFBDecipher;
exports.OFB = OFB;
exports.OFBCipher = OFBCipher;
exports.OFBDecipher = OFBDecipher;
exports.GCM = GCM;
exports.GCMCipher = GCMCipher;
exports.GCMDecipher = GCMDecipher;
exports.get = get;

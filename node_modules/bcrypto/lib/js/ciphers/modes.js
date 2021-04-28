/*!
 * modes.js - cipher modes for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 */

'use strict';

const assert = require('../../internal/assert');
const gcm = require('./gcm');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

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
    this.block = Buffer.alloc(ctx.blockSize);
    this.blockPos = -1;
    this.last = null;
    this.lastSize = 0;

    if (padding)
      this.last = Buffer.alloc(ctx.blockSize);
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

    this.blockPos = 0;
    this.lastSize = 0;

    this._init(key, iv);

    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    if (this.blockPos === -1)
      throw new Error('Cipher is not initialized.');

    const bs = this.block.length;

    let bpos = this.blockPos;
    let ilen = input.length;
    let olen = 0;
    let ipos = 0;
    let opos = 0;

    this.blockPos = (this.blockPos + ilen) % bs;

    if (this.padding)
      olen += this.lastSize;

    if (bpos > 0) {
      let want = bs - bpos;

      if (want > ilen)
        want = ilen;

      input.copy(this.block, bpos, ipos, ipos + want);

      bpos += want;
      ilen -= want;
      ipos += want;

      if (bpos < bs)
        return Buffer.alloc(0);

      olen += bs;
    }

    olen += ilen - (ilen % bs);

    const output = Buffer.alloc(olen);

    if (this.padding)
      opos += this.last.copy(output, opos, 0, this.lastSize);

    if (bpos > 0) {
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

    if (this.padding && olen > 0) {
      this.lastSize = output.copy(this.last, 0, olen - bs, olen);
      return output.slice(0, olen - bs);
    }

    return output;
  }

  final() {
    if (this.blockPos === -1)
      throw new Error('Cipher is not initialized.');

    try {
      return this._final();
    } finally {
      this.destroy();
    }
  }

  destroy() {
    this.ctx.destroy();

    this.blockPos = -1;
    this.lastSize = 0;

    for (let i = 0; i < this.blockSize; i++)
      this.block[i] = 0;

    if (this.padding) {
      for (let i = 0; i < this.blockSize; i++)
        this.last[i] = 0;
    }

    this._destroy();
  }

  setAAD(data) {
    throw new Error('Cipher is not authenticated.');
  }

  getAuthTag() {
    throw new Error('Cipher is not authenticated.');
  }

  setAuthTag(tag) {
    throw new Error('Cipher is not authenticated.');
  }

  _init() {
    throw new Error('Not implemented.');
  }

  _update() {
    throw new Error('Not implemented.');
  }

  _final() {
    throw new Error('Not implemented.');
  }

  _destroy() {
    throw new Error('Not implemented.');
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
    this.prev = null;

    if (chain)
      this.prev = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));

    if (this.chain) {
      assert(iv.length === this.blockSize);
      iv.copy(this.prev, 0);
    } else {
      assert(iv.length === 0);
    }
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      for (let i = 0; i < this.blockSize; i++)
        output[opos + i] = input[ipos + i] ^ this.prev[i];

      this.ctx.encrypt(output, opos, output, opos);

      output.copy(this.prev, 0, opos, opos + this.blockSize);
    } else {
      this.ctx.encrypt(input, ipos, output, opos);
    }
  }

  _final() {
    const left = this.blockSize - this.blockPos;
    const block = Buffer.from(this.block);

    for (let i = this.blockPos; i < this.blockSize; i++)
      block[i] = left;

    this._update(block, 0, block, 0);

    return block;
  }

  _destroy() {
    if (this.chain) {
      for (let i = 0; i < this.blockSize; i++)
        this.prev[i] = 0;
    }
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
    this.prev = null;

    if (chain)
      this.prev = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));

    if (this.chain) {
      assert(iv.length === this.blockSize);
      iv.copy(this.prev, 0);
    } else {
      assert(iv.length === 0);
    }
  }

  _update(input, ipos, output, opos) {
    if (this.chain) {
      this.ctx.decrypt(input, ipos, output, opos);

      for (let i = 0; i < this.blockSize; i++)
        output[opos + i] ^= this.prev[i];

      input.copy(this.prev, 0, ipos, ipos + this.blockSize);
    } else {
      this.ctx.decrypt(input, ipos, output, opos);
    }
  }

  _final() {
    if (this.blockPos !== 0)
      throw new Error('Bad decrypt (trailing bytes).');

    if (this.lastSize === 0)
      throw new Error('Bad decrypt (no data).');

    assert(this.lastSize === this.last.length);
    assert(this.lastSize === this.blockSize);

    const block = Buffer.from(this.last);
    const left = block[block.length - 1];

    if (left === 0 || left > this.blockSize)
      throw new Error('Bad decrypt (out of range).');

    const end = this.blockSize - left;

    for (let i = end; i < this.blockSize; i++) {
      if (block[i] !== left)
        throw new Error('Bad decrypt (padding).');
    }

    return block.slice(0, end);
  }

  _destroy() {
    if (this.chain) {
      for (let i = 0; i < this.blockSize; i++)
        this.prev[i] = 0;
    }
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

    this.state = Buffer.alloc(this.blockSize);
    this.ctr = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    iv.copy(this.ctr, 0);
  }

  _increment() {
    for (let i = this.ctr.length - 1; i >= 0; i--) {
      this.ctr[i] += 1;

      if (this.ctr[i] !== 0x00)
        break;
    }
  }

  _update(input, ipos, output, opos) {
    this.ctx.encrypt(this.ctr, 0, this.state, 0);
    this._increment();

    for (let i = 0; i < this.blockSize; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];
  }

  _final() {
    this.ctx.encrypt(this.ctr, 0, this.state, 0);

    const out = Buffer.alloc(this.blockPos);

    for (let i = 0; i < this.blockPos; i++)
      out[i] = this.block[i] ^ this.state[i];

    return out;
  }

  _destroy() {
    for (let i = 0; i < this.blockPos; i++) {
      this.state[i] = 0;
      this.ctr[i] = 0;
    }
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
    this.state = Buffer.alloc(this.blockSize);
    this.prev = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    iv.copy(this.prev, 0);
  }

  _update(input, ipos, output, opos) {
    this.ctx.encrypt(this.prev, 0, this.state, 0);

    for (let i = 0; i < this.blockSize; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];

    if (this.encrypt)
      output.copy(this.prev, 0, opos, opos + this.blockSize);
    else
      input.copy(this.prev, 0, ipos, ipos + this.blockSize);
  }

  _final() {
    this.ctx.encrypt(this.prev, 0, this.state, 0);

    const out = Buffer.alloc(this.blockPos);

    for (let i = 0; i < this.blockPos; i++)
      out[i] = this.block[i] ^ this.state[i];

    return out;
  }

  _destroy() {
    for (let i = 0; i < this.blockPos; i++) {
      this.state[i] = 0;
      this.prev[i] = 0;
    }
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

    this.state = Buffer.alloc(this.blockSize);
  }

  _init(key, iv) {
    assert(Buffer.isBuffer(iv));
    assert(iv.length === this.blockSize);

    iv.copy(this.state, 0);
  }

  _update(input, ipos, output, opos) {
    this.ctx.encrypt(this.state, 0, this.state, 0);

    for (let i = 0; i < this.blockSize; i++)
      output[opos + i] = input[ipos + i] ^ this.state[i];
  }

  _final() {
    this.ctx.encrypt(this.state, 0, this.state, 0);

    const out = Buffer.alloc(this.blockPos);

    for (let i = 0; i < this.blockPos; i++)
      out[i] = this.block[i] ^ this.state[i];

    return out;
  }

  _destroy() {
    for (let i = 0; i < this.blockPos; i++)
      this.state[i] = 0;
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
    this.tag = null;
    this.mac = null;
  }

  get blockSize() {
    return 16;
  }

  init(key, iv) {
    this.aead.init(key, iv);
    this.tag = null;
    this.mac = null;
    return this;
  }

  update(input) {
    assert(Buffer.isBuffer(input));

    const out = Buffer.from(input);

    if (this.encrypt)
      this.aead.encrypt(out);
    else
      this.aead.decrypt(out);

    return out;
  }

  final() {
    if (this.encrypt) {
      this.mac = this.aead.final(16);
      return Buffer.alloc(0);
    }

    if (!this.tag)
      throw new Error('No tag provided.');

    if (!this.aead.verify(this.tag))
      throw new Error('Invalid tag.');

    return Buffer.alloc(0);
  }

  destroy() {
    this.aead.destroy();

    if (this.tag) {
      for (let i = 0; i < this.tag.length; i++)
        this.tag[i] = 0;

      this.tag = null;
    }

    if (this.mac) {
      for (let i = 0; i < 16; i++)
        this.mac[i] = 0;

      this.mac = null;
    }
  }

  setAAD(data) {
    this.aead.aad(data);
    return this;
  }

  getAuthTag() {
    if (!this.encrypt)
      throw new Error('Must be a cipher context.');

    if (!this.mac)
      throw new Error('Cipher is not finalized.');

    return Buffer.from(this.mac);
  }

  setAuthTag(tag) {
    assert(Buffer.isBuffer(tag));

    if (this.encrypt)
      throw new Error('Must be a decipher context.');

    if (this.aead.mode === -1)
      throw new Error('Cipher is not initialized.');

    if (tag.length !== 4 && tag.length !== 8
        && (tag.length < 12 || tag.length > 16)) {
      throw new RangeError('Invalid tag size.');
    }

    this.tag = Buffer.from(tag);

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

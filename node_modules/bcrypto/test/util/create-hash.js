'use strict';

const crypto = require('crypto');

class Hash160 {
  constructor() {
    this.ctx = crypto.createHash('sha256');
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  digest() {
    const ctx = crypto.createHash('ripemd160');
    ctx.update(this.ctx.digest());
    return ctx.digest();
  }
}

class Hash256 {
  constructor() {
    this.ctx = crypto.createHash('sha256');
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  digest() {
    const ctx = crypto.createHash('sha256');
    ctx.update(this.ctx.digest());
    return ctx.digest();
  }
}

function createHash(name) {
  if (name === 'hash160' || name === 'HASH160')
    return new Hash160();

  if (name === 'hash256' || name === 'HASH256')
    return new Hash256();

  return crypto.createHash(name);
}

module.exports = createHash;

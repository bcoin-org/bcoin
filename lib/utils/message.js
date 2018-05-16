'use strict';

const assert = require('assert');

const secp256k1 = require('secp256k1');
const BufferWriter = require('bufio').BufferWriter;
const hash256 = require('bcrypto/lib/hash256');

const BITCOIN_MAGIC = 'Bitcoin Signed Message:\n';

/**
 * Returns a message hash.
 * @param {String} message
 * @param {String} [messagePrefix]
 * @return {Buffer}
 */

function magicHash(message, messagePrefix = BITCOIN_MAGIC) {
  const bw = new BufferWriter();

  bw.writeI8(messagePrefix.length);
  bw.writeString(messagePrefix);
  bw.writeVarint(message.length);
  bw.writeString(message);

  return hash256.digest(bw.render());
}

/**
 * Signs a message.
 * @param {String} message
 * @param {KeyRing} ring
 * @param {String} [messagePrefix]
 * @return {Buffer}
 */

function sign(message, ring, messagePrefix = BITCOIN_MAGIC) {
  assert(ring.getPrivateKey(), 'Cannot sign without private key.');
  const hash = magicHash(message, messagePrefix);
  const compress = 0x04 !== ring.getPublicKey().readInt8(0);
  const {signature, recovery} = secp256k1.sign(hash, ring.getPrivateKey());

  const bw = new BufferWriter();

  bw.writeI8(recovery + 27 + (compress ? 4 : 0));
  bw.writeBytes(signature);

  return bw.render();
}

/**
 * Recover a public key
 * @param {String} message
 * @param {Buffer} sig
 * @param {String} [messagePrefix]
 * @return {Buffer}
 */

function recover(message, sig, messagePrefix = BITCOIN_MAGIC) {
  assert(typeof message === 'string', 'message must be a string');
  assert(typeof messagePrefix === 'string', 'messagePrefix must be a string');
  assert(Buffer.isBuffer(sig), 'sig must be a buffer');

  const hash = magicHash(message, messagePrefix);

  assert.strictEqual(sig.length, 65, 'Invalid signature length');

  const flagByte = sig.readUInt8(0) - 27;

  assert(flagByte < 8, 'Invalid signature parameter');

  const compressed = Boolean(flagByte & 4);
  const recovery = flagByte & 3;

  return secp256k1.recover(hash, sig.slice(1), recovery, compressed);
}

module.exports = {
  sign,
  recover,
  magicHash,
  BITCOIN_MAGIC
};

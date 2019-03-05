'use strict';
/* eslint no-case-declarations: 0 */
/* eslint no-use-before-define: 0 */

const assert = require('assert');
const Output = require('./output');
const TX = require('./tx');
const MTX = require('./mtx');
const bio = require('bufio');
const {BufferMap} = require('buffer-map');
const Script = require('../script/script');
const CoinView = require('../coins/coinview');
const Witness = require('../script/witness');
const common = require('../script/common');
const KeyOriginInfo = require('../hd/keyorigin');
const Path = require('../wallet/path');
const {encoding} = bio;
const scriptTypes = common.types;
/*
 * Type Identifiers
 */

// global key
const PSBT_GLOBAL_UNSIGNED_TX = 0x00;

// input key
const PSBT_IN_NON_WITNESS_UTXO = 0x00;
const PSBT_IN_WITNESS_UTXO = 0x01;
const PSBT_IN_PARTIAL_SIG = 0x02;
const PSBT_IN_SIGHASH_TYPE = 0x03;
const PSBT_IN_REDEEM_SCRIPT = 0x04;
const PSBT_IN_WITNESS_SCRIPT = 0x05;
const PSBT_IN_BIP32_DERIVATION = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
// output key
const PSBT_OUT_REDEEM_SCRIPT = 0x00;
const PSBT_OUT_WITNESS_SCRIPT = 0x01;
const PSBT_OUT_BIP32_DERIVATION = 0x02;
// others
const MAGIC_BYTES = 0x70736274;
const GLOBAL_SEPARATOR = 0xff;

/**
 * PSBT
 * Partially Signed Bitcoin Transaction.
 * Common format to pass TX around between wallets.
 * Specified in BIP174
 * refs: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 * @alias module:primitives.PSBT
 * @property {TX} tx
 * @property {PSBTInput[]} inputs
 * @property {PSBTOutput[]} outputs
 * @property {BufferMap} unknown - Unknown key-value pair
 */
class PSBT {
  constructor(options) {
    this.tx = new TX();
    this.inputs = [];
    this.outputs = [];
    this.unknown = new BufferMap();

    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    assert(options, 'PSBT Data is required');
    assert(TX.isTX(options.tx), 'TX Data is required for PSBT');
    this.tx = TX.fromOptions(options.tx);

    for (let i = 0; i < this.tx.inputs.length; i++) {
      const input = options.inputs[i];
      this.inputs.push(new PSBTInput(input));
    }

    for (let i = 0; i < this.tx.outputs.length; i++) {
      const output = options.outputs[i];
      this.outputs.push(new PSBTOutput(output));
    }

    if (options.unknown) {
      assert(
        options.unknown instanceof BufferMap,
        'Unknown map must be BufferMap'
        );
      for (const [k, v] of options.unknown) {
        this.unknown.set(k, v);
      }
    }

    return this;
  }

  clone() {
    return new this.constructor().inject(this);
  }

  inject(psbt) {
    this.tx = psbt.tx.clone();
    for (const input of psbt.inputs) {
      this.inputs.push(input.clone());
    }

    for (const output of psbt.outputs) {
      this.outputs.push(output.clone());
    }

    for (const [k, v] of psbt.unknown) {
      this.unknown.set(Buffer.from(k), Buffer.from(v));
    }

    return this;
  }

  /**
   * Serialize the PSBT.
   * @returns {Buffer} Serialized PSBT.
   */

  toJSON() {
    return this.getJSON();
  }

  getJSON() {
    const map = {};
    for (const [k, v] of this.unknown)
      map[k.toString('hex')] = v.toString('hex');

    return {
      tx: this.tx.toJSON(),
      inputs: this.inputs.map(i => i.toJSON()),
      outputs: this.outputs.map(o => o.toJSON()),
      unknown: map,
      fee: this.getFee()
    };
  }

  fromJSON(json) {}

  static fromTX(tx, view) {
    return new this().fromTX(tx, view);
  }

  /**
   * Instantiate PSBT from tx object.
   * Similar to `SignatureData::DataFromTransaction` in bitcoind.
   * TODO: make `view` optional
   * TODO: set coin as `witnessUTXO` if possible
   * TODO: use `getScriptToSign`
   * @param {TX} tx
   */

  fromTX(tx, view) {
    assert(TX.isTX(tx), 'must pass tx');
    assert(!tx.mutable, 'do not pass mutable tx');
    view = view || new CoinView();
    this.tx = tx.clone();
    for (let i = 0; i < this.tx.inputs.length; i++) {
      this.inputs[i] = new PSBTInput();
      const input = this.tx.inputs[i];

      // there are no need to do complex stuff if it's already complete.
      const coin = view.getOutput(input.prevout);
      if (!coin)
        continue;
      if (tx.verifyInput(i, coin)) {
        this.inputs[i].finalScriptSig = input.script;
        this.inputs[i].finalScriptWitness = input.witness;
        continue;
      }

      // move scripts in Input to PSBTInput
      const wit = input.witness;
      let nextScript = coin.script;
      const stack = []; // holder for items which might be signature.
      // p2sh
      if (nextScript.isScripthash() && input.script.isScripthashInput()) {
        const redeem = input.script.getRedeem();
        this.inputs[i].redeem = redeem;
        nextScript = redeem;
        for (const i in input.script.code) {
          const item = input.script.getData(i);
          if (item !== null)
            stack.push(item);
        }
      }
      let sighashV = 0;
      // p2wsh
      if (nextScript.isWitnessScripthash() && wit.isScripthashInput()) {
        const redeem = wit.getRedeem();
        this.inputs[i].witness = redeem;
        nextScript = redeem;
        for (const item of wit.items) {
          stack.push(item);
        }
        sighashV = 1;
      }
      // p2wpkh
      if (nextScript.isWitnessPubkeyhash() && wit.isPubkeyhashInput()) {
        const [sig, pk] = wit.items;
        assert(common.isSignatureEncoding(sig) && common.isKeyEncoding(pk));
        this.inputs[i].signatures.set(pk, sig);
        sighashV = 1;
      }
      // move signatures and pubkeys if it's already present in tx.
      const [required, pubkeys] = nextScript.matchMultisig();
      if (required > 0) {
        for (const item of stack) {
          if (!common.isSignatureEncoding(item))
            continue;
          for (const p of pubkeys) {
            if (tx.checksig(i, nextScript, coin.value, item, p, sighashV)) {
              this.inputs[i].signatures.set(p, item);
            }
          }
        };
      }
    }
    // global tx should not hold any script or witness.
    for (let i = 0; i < this.tx.inputs.length; i++) {
      this.tx.inputs[i].witness = new Witness();
      this.tx.inputs[i].script = new Script();
    }
    for (let i = 0; i < this.tx.outputs.length; i++) {
      this.outputs[i] = new PSBTOutput();
    }
    return this;
  }

  fromMTX(mtx) {
    const [tx, view] = mtx.commit();
    return this.fromTX(tx, view);
  }

  static fromMTX(mtx) {
    return new this().fromMTX(mtx);
  }

  /**
   * returns user friendly representation.
   */

  inspect() {
    return this.format();
  }

  format() {
    const unknownMap = {};
    for (const [k, v] of this.unknown) {
      unknownMap[k.toString('hex')] = v.toString('hex');
    }
    return {
      tx: this.tx.format(),
      inputs: this.inputs.map(i => i.format()),
      outputs: this.outputs.map(o => o.format()),
      unknown: unknownMap
    };
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  getSize() {
    let base = 0;
    base += 4; // magic bytes
    base += 1; // separator (0xff)
    base += encoding.sizeVarlen(1); // global key
    // tx must be in old serialization format regardless of if it has
    // witness or not. So we are using `getNormalSizes()` instead of getSizes
    base += encoding.sizeVarlen(this.tx.getNormalSizes().size);
    for (const [k, v] of this.unknown) {
      base += encoding.sizeVarlen(k.length);
      base += encoding.sizeVarlen(v.length);
    }
    base += 1; // separator
    base += this.inputs.reduce((a, b) => a + b.getSize(), 0);
    base += this.outputs.reduce((a, b) => a + b.getSize(), 0);

    return base;
  }

  /**
   * Write the PSBT record to a buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeU32BE(MAGIC_BYTES);
    bw.writeU8(GLOBAL_SEPARATOR);
    this.globalsToWriter(bw);

    bw.writeU8(0x00); // sep

    for (const psbtin of this.inputs) {
      psbtin.toWriter(bw);
    }

    for (const psbtout of this.outputs) {
      psbtout.toWriter(bw);
    }

    return bw;
  }

  globalsToWriter(bw) {
    bw.writeVarint(1); // key length
    bw.writeU8(PSBT_GLOBAL_UNSIGNED_TX); // actual key
    bw.writeVarBytes(this.tx.toNormal()); // must be non-witness serialization.
    for (const [k, v] of this.unknown) {
      bw.writeVarBytes(k);
      bw.writeVarBytes(v);
    }
  }

  /**
   * @param {Buffer} data - raw data.
   * @param {String} enc - "base64" or "hex"
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    const magic = br.readU32BE();
    const sep = br.readU8();
    if (magic !== MAGIC_BYTES || sep !== GLOBAL_SEPARATOR)
      throw new Error('Bad magic bytes');

    this.globalsFromReader(br);
    assert(!this.tx.isNull(), 'no tx exists');
    for (const i of this.tx.inputs) {
      assert(
        i.script.code.length <= 0 && i.witness.items.length <= 0,
        'Global tx for psbt can not have script by itself'
      );
    }

    for (let i = 0; i < this.tx.inputs.length; i++) {
      this.inputs[i] = PSBTInput.fromReader(br);
    }

    for (let i = 0; i < this.tx.outputs.length; i++) {
      this.outputs[i] = PSBTOutput.fromReader(br);
    }

    const checkResult = this.checkSanity();
    assert(checkResult[0], checkResult[1]);
    return this;
  }

  globalsFromReader(br) {
    br.start();
    let key = br.readVarBytes();
    let value;
    while (!key.equals(Buffer.from(''))) {
      value = br.readVarBytes();
      switch(key.readUInt8()) {
        case PSBT_GLOBAL_UNSIGNED_TX:
          assert(key.length === 1, 'key for global tx should be 1 byte');
          this.tx = TX.fromRaw(value);
          break;
        default:
          assert(!this.unknown.has(key), 'Duplicate key for unknown');
          this.unknown.set(key, value);
      }
      key = br.readVarBytes();
    }
    br.end();
  };

  /**
   * get fee
   * @returns {Number} - fee.
   */
  getFee() {
    let totalIn = 0;
    for (const psbtin of this.inputs) {
      const v = psbtin.getValue();
      if (v === -1)
        return v;
      totalIn += v;
    }

    const totalOut = this.tx.getOutputValue();
    return totalIn - totalOut;
  }

  isSane() {
    const [valid] = this.checkSanity();
    return valid;
  }

  checkSanity() {
    if (
      (this.tx.inputs.length !== this.inputs.length) ||
      (this.tx.outputs.length !== this.outputs.length)
    ) {
      return [false, 'bad-psbt-field-num-mismatch', 100];
    }
    for (let i = 0; i < this.inputs.length; i++) {
      const psbtin = this.inputs[i];
      const txin = this.tx.inputs[i];
      if (!psbtin.isSane()) {
        return psbtin.checkSanity();
      }
      // if PSBT Input has txid info, check if it matches to the one of tx.
      // in bitcoin core, this is done when signing. But there are
      // no reason we should not do it beforehand.
      if (!psbtin.nonWitnessUTXO.isNull()) {
        if (!psbtin.nonWitnessUTXO.hash().equals(txin.prevout.hash)) {
          return [false, 'bad-psbtin-previous-txid-mismatch', 100];
        }
      }

      const out = psbtin.getOutput(txin);
      if (psbtin.finalScriptSig) {
        const redeem = psbtin.finalScriptSig.getRedeem();
        if (redeem && out) {
          if(!redeem.hash160().equals(out.getHash()))
            return [false, 'bad-psbtin-scriptsig-prevout-mismatch', 100];
        }
      }
    }
    return [true, 'valid', 0];
  }

  sign(ring) {
    if (Array.isArray(ring)) {
      let total = 0;
      for (const key of ring) {
        total += this.sign(key);
      }
      return total;
    }

    let total = 0;
    for (let i = 0; i < this.inputs.length; i++) {
      this.inputs[i].prepareRing(ring);
      const txin = this.tx.inputs[i];
      if (!this.inputs[i].hasOwnOutputs(ring, txin))
        continue;
      total += this.signInput(i, ring);
    }
    // TODO: finalize if possible
    return total;
  }

  /**
   * Set script for each inputs and outputs if possible.
   * Also set bip32 derivation path for both inputs and outputs only If
   * the keyring is an `WalletKey`
   * @param {KeyRing[]|WalletKey[]} ring
   * @param {Boolean} bip32 - if include bip32 path in case of WalletKey
   */

  update(ring, bip32) {
    if (Array.isArray(ring)) {
      let total = 0;
      for (const key of ring) {
        total += this.update(key, bip32);
      }
      return total;
    }
    let total = 0;
    for (let i = 0; i < this.inputs.length; i++) {
      const txin = this.tx.inputs[i];
      this.inputs[i].prepareRing(ring);
      if (!this.inputs[i].hasOwnOutputs(ring, txin))
        continue;
      this.scriptInput(i, ring, bip32);
      total++;
    }
    for (let i = 0; i < this.outputs.length; i++) {
      const txout = this.tx.outputs[i];
      this.outputs[i].prepareRing(ring);
      if (!ring.ownOutput(txout))
        continue;
      this.scriptOutput(i, ring, bip32);
      total++;
    }
    return total;
  }

  /**
   * Add following information to an input.
   * - redeem script.
   * - witness script.
   * - hd derivation path.
   * @param {Number} index
   * @param {KeyRing|WalletKey} ring
   */

  scriptInput(index, ring, bip32) {
    const psbtin = this.inputs[index];
    const txin = this.tx.inputs[index];
    const [out1, out2] = psbtin.getOutputs(txin);
    let coin;
    if (out1) {
      coin = out1;
    } else if (out2) {
      coin = out2;
    } else {
      throw new Error('psbt has not been filled with previous output');
    }
    assert(ring.ownOutput(coin));

    // 1. script
    const mtx = MTX.fromTX(this.tx.clone());
    mtx.scriptInput(index, coin, ring);
    const dummyInput = mtx.toTX().inputs[index];
    const wit = dummyInput.witness;
    if (wit.isScripthashInput())
      psbtin.witness = wit.getRedeem();

    const redeem = dummyInput.script.getRedeem();
    if (redeem)
      psbtin.redeem = redeem;

    // 2. bip32 derivation path.
    if (bip32 && ring.keyType === Path.types.HD) {
      const bip32path = KeyOriginInfo.fromWalletKey(ring);
      psbtin.keyInfo.set(ring.publicKey, bip32path);
    }
    this.inputs[index] = psbtin;
  }

  /**
   * create necessary scripts for output.
   * @param {KeyRing|WalletKey} ring
   * @param {Output} output
   */

  scriptOutput(index, ring, bip32) {
    const out = this.tx.outputs[index];
    assert(ring.ownOutput(out));
    bip32 = bip32 || true;
    const psbtout = this.outputs[index];
    // 1. script
    if (out.script.isScripthash()) {
      psbtout.redeem = ring.getRedeem(out.script.getScriptHash());
    }
    if (out.script.isWitnessScripthash()) {
      psbtout.witness = ring.getRedeem(out.script.getWitnessScripthash());
    }

    // 2. bip32 derivation path.
    if (bip32 && ring.keyType === Path.types.HD) {
      const bip32path = KeyOriginInfo.fromWalletKey(ring);
      psbtout.keyInfo.set(ring.publicKey, bip32path);
    }
    this.outputs[index] = psbtout;
  }

  /**
   * ref: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
   * Why this function is not a method for PSTInput? because
   * we must use `this.tx` to ...
   * 1. see tx input is referring to the same tx with nonWitnessUTXO.
   * 2. use `tx.signature()` for reusing the signature creation logic.
   * @param {Number} index - input index to sign.
   * @param {KeyRing} ring
   * @param {hashType} type
   */

  signInput(index, ring) {
    const psbtin = this.inputs[index];
    const txin = this.tx.inputs[index];
    if (psbtin.complete)
      // don't bother if it is already finalized.
      return true;
    if (!psbtin.hasOwnOutputs(ring, txin))
      return false;
    const check = this.checkSanity();
    assert(check[0], check[1]);

    // use `getOutputs` instead of `getOutput` to assert if we need to create
    // witness signature.
    const [script, coin, witness]  = psbtin.getScriptToSign(txin);
    return this.createSignature(
      ring,
      index,
      script,
      coin,
      witness
    );
  }

  createSignature(ring, index, prev, coin, witness) {
    const psbtin = this.inputs[index];
    const hashType = psbtin.sighash > 0 ?
      psbtin.sighash :
      Script.hashType.ALL;
    const version = witness ? 1 : 0;
    const dummy = MTX.fromTX(this.tx.clone());
    if (!witness) {
      dummy.scriptInput(index, coin, ring);
      dummy.signInput(index, coin, ring, hashType);
      const sc = dummy.inputs[index].script;
      for (let i = 0; i < sc.code.length; i++) {
        const item = sc.getData(i);
        if (
          item && common.isSignatureEncoding(item) &&
          dummy.checksig(index, prev, coin.value, item, ring.publicKey, 0)
          ) {
          psbtin.signatures.set(ring.publicKey, item);
          return 1;
        }
      }
    }
    const sig = dummy.signature(
      index,
      prev,
      coin.value,
      ring.privateKey,
      hashType,
      version
    );
    assert(dummy.checksig(index, prev, coin.value, sig, ring.publicKey, 1));
    psbtin.signatures.set(ring.publicKey, sig);
    return 1;
  }

  /**
   * Combine with another PSBT
   * @param {PSBT} psbt - another psbt to Combine
   * @param {Boolean} force - skip txid equality check. Useful for coinjoin.
   * @returns {PSBT}
   */

  combine(psbt, force) {
    // check if psbt is not the same
    if (!force || force === null) {
      assert(this.hasSameTX(psbt),'txid mismatch');
    }
    for (let i = 0; i < psbt.inputs.length; i++) {
      this.inputs[i].combine(psbt.inputs[i]);
    }
    for (let i = 0; i < psbt.outputs.length; i++) {
      this.outputs[i].combine(psbt.outputs[i]);
    }
    for (const [k, v] of psbt.unknown) {
      this.unknown.set(k, v);
    }
    return this;
  }

  hasSameTX(psbt) {
    return this.tx.hash === psbt.tx.hash;
  }

  finalize() {
    let complete = 1;
    for (let i = 0; i < this.inputs.length; i++) {
      const txin = this.tx.inputs[i];
      complete &= this.inputs[i].tryFinalize(txin);
    }
    return complete;
  };

  toTX() {
    const tx = this.tx.clone();
    for (let i = 0; i < this.inputs.length; i++) {
      const psbtin = this.inputs[i];

      if (psbtin.finalScriptSig !== null) {
        tx.inputs[i].script = psbtin.finalScriptSig;
      } else {
        tx.inputs[i].script = new Script();
      }
      if (psbtin.finalScriptWitness !== null) {
        tx.inputs[i].witness = psbtin.finalScriptWitness;
      } else {
        tx.inputs[i].witness = new Witness();
      }

      const coin = psbtin.getOutput(tx.inputs[i]);
      tx.checkInput(i, coin);
    }
    return tx;
  }

  static isPSBT(obj) {
    return obj instanceof PSBT;
  }
}

// Holder for an input KVMap
class PSBTInput {
  /**
   * @param {Options} options
   * @property {TX} nonWitnessUTXO - previous TX from which this input spends.
   *   This is required for HW Wallet to know the exact amount for the tx
   *   they are signing for.
   * @property {Output} witnessUTXO - for sighash v1, HW Wallet can verify
   *   the output amount directly. So there are no need to include whole tx,
   *   thus using Output
   * @property {Script} redeem - redeem script
   * @property {Witness} witness - witness script. Note that this is not an
   *   whole witness, but only witnessScript.
   * @property {BufferMap} keyInfo - public Key Buffer -> KeyOriginInfo map
   * @property {Number} sighash - signature hash type.
   * @property {BufferMap} signatures - public Key Buffer -> Signature map
   * @property {BufferMap} unknown - key-value pair of unknown info.
   * @property {Script} finalScriptWitness - finalized scriptWitness
   * @property {Witness} finalScriptSig - finalized scriptSig
   */

  constructor(options) {
    this.nonWitnessUTXO = new TX();
    this.witnessUTXO = new Output();
    this.sighash = -1;
    this.redeem = new Script();
    this.witness = new Script();
    this.finalScriptSig = null;
    this.finalScriptWitness = null;
    this.signatures = new BufferMap();
    this.keyInfo = new BufferMap();
    this.unknown = new BufferMap();
    if (options) {
      this.fromOptions(options);
    }
  }

  get complete() {
    return this.finalScriptSig || this.finalScriptWitness;
  }

  fromOptions(options) {
    if (options.finalScriptSig) {
      assert(typeof options.finalScriptSig === 'object');
      this.finalScriptSig = Script.fromOptions(options.finalScriptSig);
    }
    if (options.finalScriptWitness) {
      assert(typeof options.finalScriptWitness === 'object');
      this.finalScriptWitness = Witness.fromOptions(options.finalScriptWitness);
    }
    if (options.nonWitnessUTXO) {
      this.nonWitnessUTXO = TX.fromOptions(options.nonWitnessUTXO);
    }
    if (options.witnessUTXO) {
      this.witnessUTXO = Output.fromOptions(options.witnessUTXO);
    }
    if (options.sighash) {
      assert(options.sighash >>> 0 === options.sighash);
      this.sighash = options.sighash;
    }
    if (options.redeem) {
      assert(typeof options.redeem === 'object');
      this.redeem = Script.fromOptions(options.redeem);
    }
    if (options.witness) {
      assert(typeof options.witness === 'object');
      this.witness = Witness.fromOptions(options.witness);
    }
    if (options.signatures) {
      for (const [k, v] of options.signatures) {
        assert(Buffer.isBuffer(k) && Buffer.isBuffer(v));
        this.signatures.set(k, v);
      }
    }
    if (options.keyInfo) {
      for (const [k, v] of options.keyInfo) {
        assert(Buffer.isBuffer(k) && KeyOriginInfo.isKeyOriginInfo(v));
        this.keyInfo.set(k, v);
      }
    }
    if (options.unknown) {
      for (const [k, v] of options.unknown) {
        assert(Buffer.isBuffer(k) && Buffer.isBuffer(v));
        this.unknown.set(k, v);
      }
    }

    return this;
  }

  static fromOptions(options) {
    return new PSBTInput().fromOptions(options);
  }

  clone() {
    const psbtin = new PSBTInput();
    psbtin.nonWitnessUTXO = this.nonWitnessUTXO.clone();
    psbtin.witnessUTXO = this.witnessUTXO.clone();
    psbtin.witness = this.witness.clone();
    psbtin.redeem = this.redeem.clone();
    psbtin.sighash = this.sighash;
    psbtin.signatures = new BufferMap();
    for (const [k, v] of this.signatures) {
      psbtin.signatures.set(Buffer.from(k), Buffer.from(v));
    }
    for (const [k, v] of this.keyInfo) {
      psbtin.keyInfo.set(Buffer.from(k), v.clone());
    }
    for (const [k, v] of this.unknown) {
      psbtin.unknown.set(Buffer.from(k), Buffer.from(v));
    }
    if (this.finalScriptSig) {
      psbtin.finalScriptSig = this.finalScriptSig.clone();
    }
    if (this.finalScriptWitness) {
      psbtin.finalScriptWitness = this.finalScriptWitness.clone();
    }
    return psbtin;
  };

  clear() {
    this.clearForFinalize();
    this.nonWitnessUTXO = new TX();
    this.witnessUTXO = new Output();
    this.unknown.clear();
    this.finalScriptSig = null;
    this.finalScriptWitness = null;
  }

  clearForFinalize() {
    this.redeem.clear();
    this.witness.clear();
    this.sighash = -1;
    this.signatures.clear();
    this.keyInfo.clear();
  }

  getSize() {
    let base = 0;
    if (!this.nonWitnessUTXO.isNull()) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.nonWitnessUTXO.getSize()); // value
    }

    if (this.witnessUTXO.script.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.witnessUTXO.getSize()); // value
    }

    if (this.redeem.code.length > 0) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.redeem.getSize());
    }

    if (this.witness.code.length > 0) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.witness.getSize());
    }

    if (this.sighash > 0)  {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(4);
    }

    if (this.finalScriptSig) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.finalScriptSig.getSize());
    }

    if (this.finalScriptWitness) {
      base += encoding.sizeVarlen(1);
      base += encoding.sizeVarlen(this.finalScriptWitness.getSize());
    }

    for (const [k, v] of this.signatures) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.length);
    }

    for (const [k, v] of this.keyInfo) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.getSize());
    }

    for (const [k, v] of this.unknown) {
      base += encoding.sizeVarlen(k.length);
      base += encoding.sizeVarlen(v.length);
    }

    base += 1; // sep
    return base;
  }

  fromTX(tx, index) {
    const output = tx.outputs[index];
    const type = output.script.getTypes();
    // If output has possibility of being witness UTXO. we store both
    // witnessUTXO and nonWitnessUTXO in case it is not.
    if (
      type & 0x80 || // witness scriptPubKey
      type === scriptTypes.SCRIPTHASH || // ps2h
      type === scriptTypes.MULTISIG
    ) {
      this.witnessUTXO = output;
      this.nonWitnessUTXO = tx;
    } else {
      this.nonWitnessUTXO = tx;
    }
    return this;
  }

  static fromTX(tx, index) {
    return new this().fromTX(tx, index);
  }

  combine(psbtIn) {
    assert(
      psbtIn instanceof PSBTInput,
      'PSBTInput can only be combined with PSBTInput'
    );
    if(this.nonWitnessUTXO.isNull() && !psbtIn.nonWitnessUTXO.isNull())
      this.nonWitnessUTXO = psbtIn.this.nonWitnessUTXO;
    if (this.redeem.code.length === 0 && psbtIn.redeem.code.length > 0)
      this.redeem = psbtIn.redeem;
    if (!this.witness.code.length === 0 && psbtIn.witness.code.length > 0)
      this.witness = psbtIn.witness;

    if (!this.finalScriptSig && psbtIn.finalScriptSig)
      this.finalScriptSig = psbtIn.finalScriptSig;
    if (!this.finalScriptWitness && psbtIn.finalScriptWitness)
      this.finalScriptWitness = psbtIn.finalScriptWitness;
    if(this.witnessUTXO.script.code.length === 0 &&
      psbtIn.witnessUTXO.script.code.length > 0) {
      this.witnessUTXO = psbtIn.witnessUTXO;
      // Clear out any non-witness utxo when we set a witness one.
      this.nonWitnessUTXO.clear();
    }

    for (const [k, v] of psbtIn.signatures) {
      this.signatures.set(k, v);
    }

    for (const [k, v] of psbtIn.keyInfo) {
      this.keyInfo.set(k, v);
    }

    for (const [k, v] of psbtIn.unknown) {
      this.unknown.set(k, v);
    }
    return this;
  }

  prepareRing(ring) {
    if (this.witness.code.length > 0) {
      const [, pk] = this.witness.matchMultisig();
      if (!pk || pk.findIndex(k => k.equals(ring.publicKey)) === -1)
        return;
      ring.witness = true;
      ring.script = this.witness;
      if (this.redeem.isProgram())
        ring.nested = true;
    } else if (this.redeem.code.length > 0) {
      const [, pk] = this.redeem.matchMultisig();
      if (!pk || pk.findIndex(k => k.equals(ring.publicKey)) === -1)
        return;
      ring.script = this.redeem;
    }
    ring.refresh();
  }

  tryFinalize(txin) {
    if (this.complete)
      return true;
    if (this.signatures.size < 1)
      return false;
    const [script, , isWitness] = this.getScriptToSign(txin);
    // 1. non-multisig
    if (!isWitness && script.isPubkeyhash()) { // p2pkh
      for (const [pk, sig] of this.signatures) {
        const sc = new Script();
        sc.pushData(sig);
        sc.pushData(pk);
        sc.compile();
        this.finalScriptSig = sc;
        return true;
      }
    }

    if (isWitness && script.isPubkeyhash()) { // p2wpkh
      if (this.redeem.isWitnessPubkeyhash()) { // p2sh-p2wpkh
        const sc = new Script();
        sc.pushData(this.redeem.toRaw());
        sc.compile();
        this.finalScriptSig = sc;
      }
      for (const [pk, sig] of this.signatures) {
        const wit = new Witness();
        wit.push(sig);
        wit.push(pk);
        this.finalScriptWitness = wit;
        return true;
      }
    }

    // 2. multisig
    const [m, pubkeys] = script.matchMultisig();
    assert(m !== -1, 'unknown input type');

    const sigs = [];
    for (const k of pubkeys) {
      const sig = this.signatures.get(k);
      if (sig)
        sigs.push(sig);
    }
    if (sigs.length < m)
      return false;

    if (isWitness) {
      const scriptWitness = new Witness();
      // witness requires empty buffer instead of `OP_0` as its first item.
      scriptWitness.push(Buffer.from(''));
      for (const s of sigs) {
        scriptWitness.push(s);
      }
      scriptWitness.push(script.toRaw());
      this.finalScriptWitness = scriptWitness;
      // for p2sh nested
      if (this.redeem.isProgram()) {
        this.finalScriptSig = new Script().pushData(this.redeem.toRaw());
        this.finalScriptSig.compile();
      }
      this.clearForFinalize();
      return true;
    }

    const scriptSig = new Script();
    scriptSig.pushOp(common.opcodes.OP_0);
    for (const s of sigs) {
      scriptSig.pushData(s);
    }
    scriptSig.pushData(this.redeem.toRaw());
    this.finalScriptSig = scriptSig;
    this.finalScriptSig.compile();
    this.clearForFinalize();
    return true;
  }

  /**
   * @private
   * @returns {Script, Output}
   */

  getScriptToSign(txin) {
    assert(txin);
    const [out1, out2] = this.getOutputs(txin);
    let coin;
    if (out1) {
      coin = out1;
    } else if (out2) {
      coin = out2;
    }
    if (!coin)
      throw new Error('PSBTInput has no prevout info');
    const requireWitnessSig = out1 === null;

    let nextScript = coin.script;
    let witness = false;
    // p2sh
    if (nextScript.isScripthash()) {
      if (!this.redeem.hash160().equals(coin.script.getScripthash()))
        throw new Error('psbt has no good redeem script');
      nextScript = this.redeem;
    }

    // p2wsh
    if (nextScript.isWitnessScripthash()) {
      if (!this.witness.forWitness().equals(nextScript))
        throw new Error('witness mismatch');
      nextScript = this.witness;
      witness = true;
    }

    // p2wpkh
    if (nextScript.isWitnessPubkeyhash()) {
      witness = true;
      nextScript = Script.fromPubkeyhash(nextScript.getWitnessPubkeyhash());
    }
    if (requireWitnessSig)
      assert(witness);
    return [nextScript, coin, witness];
  }

  hasOwnOutputs(ring, txin) {
    const [out1, out2] = this.getOutputs(txin);
    if (!out1 && !out2)
      return false;
    let result1;
    let result2;
    if (out1)
      result1 = ring.ownOutput(out1);
    if (out2)
      result2 = ring.ownOutput(out2);
    return result1 || result2;
  }

  getOutput(txin) {
    const [out1, out2] = this.getOutputs(txin);
    if (out1 && out2) {
      assert(out1.equals(out2), 'witness and non-witness output differs');
      return out1;
    }
    if (out1)
      return out1;
    if (out2)
      return out2;

    return null;
  }

  getOutputs(txin) {
    let out1;
    if (!this.nonWitnessUTXO.isNull()) {
      if (txin)
        out1 = this.nonWitnessUTXO.outputs[txin.prevout.index];
    }
    let out2;
    if (this.witnessUTXO.script.code.length > 0) {
      out2 = this.witnessUTXO;
    }

    return [out1, out2];
  }

  getValue() {
    const out = this.getOutput();
    if (!out || !out.value)
      return -1;
    return out.value;
  }

  isSane() {
    const [valid] = this.checkSanity();
    return valid;
  }

  checkSanity() {
    if (this.witness.code.length > 0 && !this.witnessUTXO)
      return [false, 'bad-psbtin-witness-script-with-no-utxo', 100];
    if (this.finalScriptWitness && !this.witnessUTXO)
      return [false, 'bad-psbtin-witness-script-with-no-utxo', 100];
    return [true, 'valid', 0];
  }

  toJSON() {
    return this.getJSON();
  }

  getJSON() {
    const signaturesMap = {};
    for (const [k, v] of this.signatures) {
      signaturesMap[k.toString('hex')] = v.toString('hex');
    }

    const keyInfoMap = {};
    for (const [k, v] of this.keyInfo) {
      keyInfoMap[k.toString('hex')] = v.toJSON();
    }

    const unknownMap = {};
    for (const [k, v] of this.unknown) {
      unknownMap[k.toString('hex')] = v.toString('hex');
    }

    return {
      nonWitnessUTXO: this.nonWitnessUTXO.toJSON(),
      witnessUTXO: this.witnessUTXO.toJSON(),
      sighash: this.sighash,
      redeem: this.redeem.toJSON(),
      witness: this.witness.toJSON(),
      finalScriptSig: this.finalScriptSig ? this.finalScriptSig.toJSON() : '',
      finalScriptWitness: this.finalScriptWitness ?
        this.finalScriptWitness.toJSON() :
        '',
      signatures: signaturesMap,
      keyInfo: keyInfoMap,
      unknown: unknownMap
    };
  }

  inspect() {
    return this.format();
  }

  format() {
    const keyInfoMap = [];
    for (const [k, v] of this.keyInfo) {
      const info = {};
      info['pubkey'] = k.toString('hex');
      info['path'] = v.format();
      keyInfoMap.push(info);
    }

    return {
      nonWitnessUTXO: this.nonWitnessUTXO.format(),
      witnessUTXO: this.witnessUTXO.toJSON(),
      sighash: this.sighash,
      redeem: this.redeem,
      witness: this.witness,
      finalScriptSig: this.finalScriptSig ? this.finalScriptSig.toString() : '',
      finalScriptWitness: this.finalScriptWitness ?
        this.finalScriptWitness.toString() : '',
      keyInfo: keyInfoMap
    };
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  toWriter(bw) {
    if (!this.nonWitnessUTXO.isNull()) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_NON_WITNESS_UTXO);
      bw.writeVarBytes(this.nonWitnessUTXO.toRaw());
    }

    if (this.witnessUTXO.script.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_WITNESS_UTXO);
      bw.writeVarBytes(this.witnessUTXO.toRaw());
    }

    if (this.redeem.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_REDEEM_SCRIPT);
      bw.writeVarBytes(this.redeem.toRaw());
    }

    if (this.witness.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_WITNESS_SCRIPT);
      bw.writeVarBytes(this.witness.toRaw());
    }

    if (this.sighash > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_SIGHASH_TYPE);
      bw.writeVarint(4);
      bw.writeU32(this.sighash);
    }

    if (this.finalScriptSig) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_FINAL_SCRIPTSIG);
      bw.writeVarBytes(this.finalScriptSig.toRaw());
    }

    if (this.finalScriptWitness) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_IN_FINAL_SCRIPTWITNESS);
      bw.writeVarBytes(this.finalScriptWitness.toRaw());
    }

    for (const [k, v] of this.signatures) {
      bw.writeVarBytes(Buffer.concat([Buffer.from([PSBT_IN_PARTIAL_SIG]), k]));
      bw.writeVarBytes(v);
    }

    for (const [k, v] of this.keyInfo) {
      bw.writeVarBytes(
          Buffer.concat([Buffer.from([PSBT_IN_BIP32_DERIVATION]), k])
        );
      bw.writeVarBytes(v.toRaw());
    }

    for (const [k, v] of this.unknown) {
      bw.writeVarBytes(k);
      bw.writeVarBytes(v);
    }
    bw.writeU8(0x00); // sep

    return bw;
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  fromRaw(data) {
    assert(Buffer.isBuffer(data), 'must pass buffer');
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    let key = br.readVarBytes();
    let value;
    let pubkey;
    while (!key.equals(Buffer.from(''))) {
      value = br.readVarBytes();
      switch(key.readUInt8()) {
        case PSBT_IN_NON_WITNESS_UTXO:
          assert(
            this.nonWitnessUTXO.isNull(),
            'duplicate key for nonWitnessUTXO'
          );
          assert(key.length === 1, 'key for nonWitnessUTXO should be 1 byte');
          this.nonWitnessUTXO = TX.fromRaw(value);
          break;
        case PSBT_IN_WITNESS_UTXO:
          assert(
             this.witnessUTXO.script.code.length === 0,
            'duplicate key for witnessUTXO'
            );
          assert(key.length === 1, 'key for witnessUTXO should be 1 byte');
          this.witnessUTXO = Output.fromRaw(value);
          break;
        case PSBT_IN_PARTIAL_SIG:
          pubkey = key.slice(1);
          assert(!this.signatures.has(pubkey), 'duplicate key for signature');
          assert(
            pubkey.length === 33 || pubkey.length === 65, // compressed or not.
            'public key size for partial sig is not correct.'
          );
          this.signatures.set(pubkey, value);
          break;
        case PSBT_IN_SIGHASH_TYPE:
          assert(this.sighash === -1, 'duplicate key for sighash');
          assert(key.length === 1, 'key for sighash should be 1 byte');
          this.sighash = value.readUInt8();
          break;
        case PSBT_IN_REDEEM_SCRIPT:
          assert(
              this.redeem.code.length === 0,
              'duplicate key for redeem script'
            );
          assert(key.length === 1, 'key for redeem script should be 1 byte');
          this.redeem = Script.fromRaw(value);
          break;
        case PSBT_IN_WITNESS_SCRIPT:
          assert(
              this.witness.code.length === 0,
              'duplicate key for witness script'
            );
          assert(key.length === 1, 'key for witness script should be 1 byte');
          this.witness = Script.fromRaw(value);
          break;
        case PSBT_IN_BIP32_DERIVATION:
          // TODO: needs assertion?
          pubkey = key.slice(1);
          assert(
              common.isKeyEncoding(pubkey),
              'bip32 derivation path must hold pubkey.'
            );
          const keyInfo = KeyOriginInfo.fromRaw(value);
          this.keyInfo.set(pubkey, keyInfo);
          break;
        case PSBT_IN_FINAL_SCRIPTSIG:
          assert(!this.finalScriptSig, 'duplicate key for scriptSig.');
          assert(key.length === 1, 'key for scriptSig should be 1 byte');
          this.finalScriptSig = Script.fromRaw(value);
          break;
        case PSBT_IN_FINAL_SCRIPTWITNESS:
          assert(!this.finalScriptWitness, 'duplicate key for scriptWitness.');
          assert(key.length === 1, 'key for scriptWitness should be 1 byte');
          this.finalScriptWitness = Witness.fromRaw(value);
          break;
        default:
          assert(!this.unknown.has(key), 'Duplicate key for unknown');
          this.unknown.set(key, value);
      }
      key = br.readVarBytes();
    }
    br.end();
    return this;
  }

  static isPSBTInput(obj) {
    return obj instanceof PSBTInput;
  }
}

// Holder for an output KVMap
class PSBTOutput {
  constructor(options) {
    this.redeem = new Script();
    this.witness = new Script();
    this.keyInfo = new BufferMap();
    this.unknown = new BufferMap();
    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    if (options.redeem) {
      assert(typeof options.redeem === 'object');
      this.redeem = Script.fromOptions(options.redeem);
    }
    if (options.witness) {
      assert(typeof options.witness === 'object');
      this.redeem = Script.fromOptions(options.witness);
    }
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  clone() {
    const psbtout = new PSBTOutput();
    psbtout.redeem = this.redeem.clone();
    psbtout.witness = this.witness.clone();
    for (const [k, v] of this.keyInfo) {
      psbtout.keyInfo.set(Buffer.from(k), v.clone());
    }
    for (const [k, v] of this.unknown) {
      psbtout.unknown.set(Buffer.from(k), Buffer.from(v));
    }
    return psbtout;
  }

  combine(out) {
    assert(PSBTOutput.isPSBTOutput(out));
    if (this.redeem.code.length === 0 && out.redeem.code.length > 0)
      this.redeem = out.redeem;
    if (this.witness.code.length === 0 && out.witness.code.length > 0)
      this.witness = out.witness;
    for (const [k, v] of out.keyInfo) {
      this.keyInfo.set(k, v);
    }
    for (const [k, v] of out.unknown) {
      this.unknown.set(k, v);
    }
    return this;
  }

  prepareRing(ring) {
    if (this.witness.code.length > 0) {
      ring.witness = true;
      ring.script = this.witness;
      if (this.redeem.isProgram())
        ring.nested = true;
    } else if (this.redeem.code.length > 0) {
      ring.script = this.redeem;
    }
    ring.refresh();
  }

  addTX(tx, index) {
    assert(index >>> 0, 'must provide index');
    if (tx.inputs[index].redeem)
      this.redeem = tx.inputs[index].redeem;
    if (tx.inputs[index].witness)
      this.witness = tx.inputs[index].redeem;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  toWriter(bw) {
    if (this.redeem.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_OUT_REDEEM_SCRIPT);
      bw.writeVarBytes(this.redeem.toRaw());
    }

    if (this.witness.code.length > 0) {
      bw.writeVarint(1);
      bw.writeU8(PSBT_OUT_WITNESS_SCRIPT);
      bw.writeVarBytes(this.witness.toRaw());
    }

    for (const [k, v] of this.keyInfo) {
      bw.writeVarBytes(
          Buffer.concat([Buffer.from([PSBT_OUT_BIP32_DERIVATION]), k])
        );
      bw.writeVarBytes(v.toRaw());
    }

    for (const [k, v] of this.unknown) {
      bw.writeVarBytes(k);
      bw.writeVarBytes(v);
    }

    bw.writeU8(0x00); // sep
    return bw;
  }

  toJSON() {
    return this.getJSON();
  }

  getSize() {
    let base = 0;
    if (this.redeem.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.redeem.getSize()); // value
    }
    if (this.witness.code.length > 0) {
      base += encoding.sizeVarlen(1); // key
      base += encoding.sizeVarlen(this.witness.getSize()); // value
    }
    for (const [k, v] of this.keyInfo) {
      base += encoding.sizeVarlen(1 + k.length);
      base += encoding.sizeVarlen(v.getSize());
    }

    for (const [k, v] of this.unknown) {
      base += encoding.sizeVarlen(k.length);
      base += encoding.sizeVarlen(v.length);
    }

    base += 1;
    return base;
  }

  getJSON() {
    const keyInfoMap = {};
    for (const [k, v] of this.keyInfo) {
      keyInfoMap[k.toString('hex')] = v.toJSON();
    }

    const unknownMap = {};
    for (const [k, v] of this.unknown) {
      unknownMap[k.toString('hex')] = v.toString('hex');
    }
    return {
      redeem: this.redeem.toJSON(),
      witness: this.witness.toJSON(),
      keyInfo: keyInfoMap,
      unknown: unknownMap
    };
  }

  inspect() {
    return this.format();
  }

  format() {
    return {
      redeem: this.redeem,
      witness: this.witness,
      keyInfo: this.keyInfo,
      unknown: this.unknown
    };
  }

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw();
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    br.start();
    let key = br.readVarBytes();
    let value;
    let pubkey;
    while(!key.equals(Buffer.from(''))) {
      value = br.readVarBytes();
      switch(key.readUInt8()) {
        case PSBT_OUT_REDEEM_SCRIPT:
          assert(
              this.redeem.code.length === 0,
              'duplicate key for output redeem script.'
            );
          assert(key.length === 1, 'key for redeem script should be 1 byte');
          this.redeem = Script.fromRaw(value);
          break;
        case PSBT_OUT_WITNESS_SCRIPT:
          assert(
              !this.witness.items.length === 0,
              'duplicate key for output witness script.'
            );
          assert(key.length === 1, 'key for witness script should be 1 byte');
          this.witness = Script.fromRaw(value);
          break;
        case PSBT_OUT_BIP32_DERIVATION:
          pubkey = key.slice(1);
          assert(
              common.isKeyEncoding(pubkey),
              'bip32 derivation path must hold pubkey.'
            );
          const keyInfo = KeyOriginInfo.fromRaw(value);
          this.keyInfo.set(pubkey, keyInfo);
          break;
        default:
          assert(!this.unknown.has(key), 'Duplicate key for unknown');
          this.unknown.set(key, value);
          break;
      }
      key = br.readVarBytes();
    }
    br.end();
    return this;
  }

  static isPSBTOutput(out) {
    return out instanceof PSBTOutput;
  }
}

module.exports = PSBT;

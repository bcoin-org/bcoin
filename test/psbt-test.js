/* eslint-env mocha */
'use strict';

const PSBT = require('../lib/primitives/psbt');
const KeyRing = require('../lib/primitives/keyring');
const Outpoint = require('../lib/primitives/outpoint');
const Coin = require('../lib/primitives/coin');
const Script = require('../lib/script/script');
const common = require('../lib/script/common');
const HDPrivateKey = require('../lib/hd/private');
const KeyOriginInfo = require('../lib/hd/keyorigin');
const Amount = require('../lib/btc/amount');
const MTX = require('../lib/primitives/mtx');
const TX = require('../lib/primitives/tx');

const data = require('./data/psbt.json');

const util = require('../lib/utils/util');
const hash160 = require('bcrypto/lib/hash160');
const assert = require('./util/assert');

function assertPSBTEqual(actual, expected) {
  assert.bufferEqual(
    actual.tx.hash(),
    expected.tx.hash(),
    'tx hash must be same'
  );
  assert.strictEqual(actual.inputs.length, expected.inputs.length);
  assert.strictEqual(actual.outputs.length, expected.outputs.length);

  for (const i in expected.inputs) {
    const e = expected.inputs[i];
    const a = actual.inputs[i];
    if (!e.nonWitnessUTXO.isNull()) {
      assert(!a.nonWitnessUTXO.isNull(), 'nonWitnessUTXO must be same');
      assert.bufferEqual(
        e.nonWitnessUTXO.hash(),
        a.nonWitnessUTXO.hash(),
        'nonWitnessUTXO must be same'
      );
    }

    assert(e.witnessUTXO.equals(a.witnessUTXO),'witnessUTXO must be same');
    assert(e.redeem.equals(a.redeem), 'redeem must be same');
    assert(e.witness.equals(a.witness), 'witness must be same');
    assert.strictEqual(e.sighash, a.sighash, 'sighash must be same');

    assert.bufferMapEqual(
      a.keyInfo,
      e.keyInfo,
      compareKeyInfo,
      'mismatch in KeyInfo'
    );
    assert.bufferMapEqual(a.signatures, e.signatures);
    assert.bufferMapEqual(a.unknown, e.unknown);

    if (e.finalScriptSig) {
      assert(
        e.finalScriptSig.equals(a.finalScriptSig),
      'finalScriptSig must be same'
      );
    }

    if (e.finalScriptWitness) {
      for (let i = 0; i < e.finalScriptWitness.items.length;i++) {
        const itemE = e.finalScriptWitness.items[i];
        const itemA = a.finalScriptWitness.items[i];
        assert.bufferEqual(itemE, itemA);
      }
    }
  };

  for (const i in expected.output) {
    const e = expected.output[i];
    const a = actual.output[i];
    assert(e.redeem.equals(a.redeem), 'redeem must be same');
    assert(e.witness.equals(a.witness), 'witness must be same');
    assert.bufferMapEqual(a.keyInfo, e.keyInfo, compareKeyInfo);
    assert.bufferMapEqual(a.unknown, e.unknown);
  };
}

function compareKeyInfo(a, b, message) {
  assert(a.equals(b), message);
}

function assertFinalized(psbt, tx, witness) {
  if (witness) {
    const actual = psbt.inputs[0].finalScriptWitness;
    const expected = tx.inputs[0].witness;
    for (const i in actual.items) {
      assert.bufferEqual(
        actual.items[i],
        expected.items[i],
      );
    }
  } else {
    const actual = psbt.inputs[0].finalScriptSig;
    const expected = tx.inputs[0].script;
    assert(actual.equals(expected));
  }
}

/**
 * returns tx with 1 input and 1 output.
 * @param {KeyRing} ring - key to sign input.
 * @param {String} type - type of input. e.g. "p2wsh", "p2sh-p2wpkh".
 */

function templateTX(type, numSign, m, n, ringOutput) {
  const keys = [];
  for (let i = 0; i < n; i++) {
    keys.push(KeyRing.generate());
    keys[i].witness = type.endsWith('p2wpkh') || type.endsWith('p2wsh');
    keys[i].nested = type === 'p2sh-p2wsh' || type === 'p2sh-p2wpkh';
    n = n <= 1 ? 1 : n;
    m = m <= 1 ? 1 : m;
  }
  for (let i = 0; i < n; i++) {
    keys[i].script = type.endsWith('p2wsh') || type === 'p2sh' ?
      Script.fromMultisig(m, n, keys.map(k => k.publicKey)) :
      null;
  }

  const fundValue = Amount.fromBTC('0.1').toValue();
  const cb = new MTX();
  cb.addInput({
    prevout: new Outpoint(),
    script: new Script()
  });
  cb.addOutput({
    address: keys[0].getAddress(),
    value: fundValue
  });
  const coin = Coin.fromTX(cb.toTX(), 0, -1);

  const mtx = new MTX();
  mtx.addTX(cb, 0);
  mtx.scriptInput(0, coin, keys[0]);
  ringOutput = ringOutput || KeyRing.generate();
  const outValue = Amount.fromBTC('0.08').toValue();
  mtx.addOutput(ringOutput.getAddress(), outValue);

  if (numSign > 0) {
    for (let i = 0; i < numSign; i++) {
      mtx.signInput(0, coin, keys[i]);
    }
  }

  return [keys, ringOutput, mtx, cb];
}

function commonAssertion(psbt) {
  for (const i of psbt.tx.inputs) {
    assert.strictEqual(
       i.script.code.length, 0,
      'psbt should not hold script in global transaction'
    );
    assert.strictEqual(
      i.witness.items.length, 0,
      'psbt should not hold witness in global transaction'
    );
  }
  assert(
    psbt.inputs.length === psbt.tx.inputs.length &&
    psbt.outputs.length === psbt.tx.outputs.length,
    'psbt should have same number of [in|out]puts with global tx'
  );
}

function checkSig(psbt, cb, publicKey, type) {
  const sig = psbt.inputs[0].signatures.get(publicKey);
  assert(sig);
  let prev = cb.outputs[0].script;
  let v = 0;
  if (type === 'p2sh' || type === 'p2sh-p2wpkh')
    prev = psbt.inputs[0].redeem;
  if (type === 'p2wsh' || type === 'p2sh-p2wsh')
    prev = psbt.inputs[0].witness;
  if (type.endsWith('p2wsh') || type.endsWith('p2wpkh'))
    v = 1;
  if (type.endsWith('p2wpkh'))
    prev = Script.fromPubkeyhash(prev.getWitnessPubkeyhash());
  const dummy = psbt.tx.clone();
  const value = cb.outputs[0].value;
  assert(
    dummy.checksig(0, prev, value, sig, publicKey, v),
    'malformed signature'
  );
}

describe('Partially Signed Bitcoin Transaction', () => {
  for (const i in data.invalid) {
    const testcase = data.invalid[i];
    it(`should fail to decode invalid psbt ${i}`, () => {
      let err;
      let result;
      try {
        result = PSBT.fromRaw(testcase, 'base64');
      } catch (e) {
        err = e;
      }
      assert.typeOf(err, 'error', result);
    });
  }

  for (const i in data.valid) {
    const testcase = data.valid[i];
    it(`should encode and decode psbt ${i} without changing property`, () => {
      const testcaseBuf = Buffer.from(testcase, 'base64');
      const psbt = PSBT.fromRaw(testcaseBuf);
      const raw = psbt.toRaw();
      const psbt2 = PSBT.fromRaw(raw);
      assertPSBTEqual(psbt2, psbt);
    });
  };

  for (const i in data.invalidForSigners) {
    const testcase = data.invalidForSigners[i];
    it(`should parse data but fails to sign for psbt ${i}`, () => {
      const psbt = PSBT.fromRaw(testcase, 'base64');
      const raw = psbt.toRaw();
      const psbt2 = PSBT.fromRaw(raw);
      assertPSBTEqual(psbt, psbt2);
      // TODO: assert it fails to check before signing.
    });
  }

  describe('Creator', () => {
    for (const sign of [true, false]) {
      const suffix = sign ? 'signed' : 'unsigned';
      it(`should instantiate from tx with ${suffix} p2wpkh input`, () => {
        const numSign = sign ? 1 : 0;
        const [, ringOut, mtx] = templateTX('p2wpkh', numSign, 1, 1);

        const [tx, view] = mtx.commit();
        const psbt = PSBT.fromTX(tx, view);

        commonAssertion(psbt);

        const wit = psbt.inputs[0].witness;
        assert(
          wit.equals(new Script()),
          'witness script in PSBTInput should be empty for p2wpkh input'
        );
        assert(
          ringOut.ownOutput(psbt.tx.outputs[0]),
          'psbt should preserve original tx output'
        );
        if (sign)
          assertFinalized(psbt, mtx, true);
    });
  };

    for (const numSign of [0, 1, 2]) {
      for (const type of ['p2wsh', 'p2sh-p2wsh']) {
        it(`can create from tx with ${numSign} signed ${type} input`, () => {
          const [rings, , mtx] = templateTX(type, numSign, 2, 2);

          const [tx, view] = mtx.commit();
          const psbt = PSBT.fromTX(tx, view);

          commonAssertion(psbt);
          const wit = psbt.inputs[0].witness;
          if (numSign === 0) {
            assert(
              wit.equals(rings[0].script),
              'witness script for p2wsh must be copied to PSBTInput'
            );
          }
          if (numSign === 1) {
            const witExpected = tx.inputs[0].witness;
            const [sigE] = witExpected.items
              .filter(i => common.isSignatureEncoding(i));
            const sig = psbt.inputs[0].signatures.get(rings[0].publicKey);
            assert.bufferEqual(sig, sigE, 'must preserve signature');
          }
          if (numSign === 2)
            assertFinalized(psbt, mtx, true);
        });
      }
    }
  });

  describe('Signer', () => {
    const t = ['p2pkh', 'p2sh', 'p2wsh', 'p2wpkh','p2sh-p2wsh', 'p2sh-p2wpkh'];
    const multisigType = ['p2sh', 'p2wsh', 'p2sh-p2wsh'];
    for (const type of t) {
      for (const sighash of Object.keys(common.hashTypeByVal)) {
        const val = common.hashTypeByVal[sighash];
        it(`should sign input for ${type} with sighash ${val}`, () => {
          const [rings, , mtx, cb] = templateTX(type, 0, 2, 2);
          const psbt = PSBT.fromMTX(mtx);
          assert.strictEqual(psbt.inputs[0].signatures.size, 0);
          psbt.inputs[0].nonWitnessUTXO = cb.toTX();
          psbt.inputs[0].sighash = parseInt(sighash);

          psbt.signInput(0, rings[0]);
          assert.strictEqual(psbt.inputs[0].signatures.size, 1);
          checkSig(psbt, cb, rings[0].publicKey, type);

          if (multisigType.findIndex(t => t !== -1)) {
            psbt.signInput(0, rings[1]);
            assert.strictEqual(psbt.inputs[0].signatures.size, 2);
            checkSig(psbt, cb, rings[1].publicKey, type);
          }
        });
      }
    }
  });

  describe('Combiner', () => {
    it('should merge the psbt with the same txid', () => {
    });
    it('should merge the psbt with a different txid', () => {});
  });

  describe('Finalizer & TX Extractor', () => {
    for (const type of ['p2sh', 'p2wsh', 'p2sh-p2wsh']) {
      it(`should finalize fully signed ${type} multisig`, () => {
        const [keys, , mtx, cb] = templateTX(type , 1, 2, 2);
        const psbt = PSBT.fromMTX(mtx);
        psbt.inputs[0].nonWitnessUTXO = cb;
        psbt.sign(keys);
        assert(psbt.inputs[0].finalScriptSig === null);
        assert(psbt.inputs[0].finalScriptWitness === null);
        psbt.finalize();

        assert(psbt.inputs.every(i => i.witness.code.length === 0));
        assert(psbt.inputs.every(i => i.redeem.code.length === 0));
        assert(psbt.inputs.every(i => i.signatures.size === 0));
        if (type === 'p2sh')
          assert(psbt.inputs[0].finalScriptSig.isScripthashInput());
        if (type.endsWith('p2wsh'))
          assert(psbt.inputs[0].finalScriptWitness.isScripthashInput());

        // TX Extractor
        const tx = psbt.toTX();
        assert(tx.verify(mtx.view));
        const coin = mtx.view.getOutput(tx.inputs[0].prevout);
        tx.checkInput(0, coin);
      });

      it(`should fail to finalize partially signed ${type} multisig`, () => {
        const [, , mtx] = templateTX(type , 1, 2, 2);
        const psbt = PSBT.fromMTX(mtx);
        let err;
        try {
          psbt.finalize();
        } catch (e) {
          err = e;
        }
        assert.typeOf(err, 'error');
      });

      for (const type2 of ['p2pkh', 'p2wpkh', 'p2sh-p2wpkh']) {
        it (`should finalize psbt with 1. ${type} and 2. ${type2}`, () => {
          const [keys, , mtx, cb] = templateTX(type, 0, 2, 2);
          const ring = KeyRing.generate();
          ring.witness = type2.endsWith('p2wpkh');
          ring.nested = type2.startsWith('p2sh');
          ring.refresh();
          const cb2 = new MTX();
          cb2.addInput({
            prevout: new Outpoint(),
            script: new Script()
          });
          cb2.addOutput({address: ring.getAddress(), value: 100});
          mtx.addTX(cb2, 0);
          mtx.scriptInput(0, cb.outputs[0], keys);
          mtx.scriptInput(1, cb2.outputs[0], ring);
          mtx.sign(keys);
          const [tx, view] = mtx.commit();
          const psbt = PSBT.fromTX(tx, view);
          psbt.inputs[0].nonWitnessUTXO = cb;
          psbt.inputs[1].nonWitnessUTXO = cb2;
          psbt.sign(ring);
          psbt.finalize();
          const finalTX = psbt.toTX();
          finalTX.check(view);
        });
      }
    }
  });

  it('should pass the longest test in BIP174', () => {
   /* eslint-disable */
   const d = data.final;
    const master = HDPrivateKey.fromBase58(d.master, 'testnet');
    assert(d.master, master.xprivkey());
    const mtx = new MTX({version: 2});

    mtx.addOutput({
      script: Script.fromRaw(d.out1.script, 'hex'),
      value: Amount.fromBTC(d.out1.value).toValue()
    });
    mtx.addOutput({
      script: Script.fromRaw(d.out2.script, 'hex'),
      value: Amount.fromBTC(d.out2.value).toValue()
    });

    mtx.addInput({
      prevout: {
        hash: util.fromRev(d.in1.txid),
        index: d.in1.index
      }
    });
    mtx.addInput({
      prevout: {
        hash: util.fromRev(d.in2.txid),
        index: d.in2.index
      }
    });
    const psbt = PSBT.fromMTX(mtx);
    let expected = PSBT.fromRaw(d.psbt1, 'base64')
    assertPSBTEqual(psbt, expected);

    // update
    const redeem1 = Script.fromRaw(d.redeem1, 'hex');
    const redeem2 = Script.fromRaw(d.redeem2, 'hex');
    const witness1 = Script.fromRaw(d.witness1, 'hex');
    const prevtx1 = TX.fromRaw(d.prevtx1, 'hex');
    const prevtx2 = TX.fromRaw(d.prevtx2, 'hex');
    const rings = [d.pubkey1, d.pubkey2, d.pubkey3, d.pubkey4, d.pubkey5, d.pubkey6]
      .map(p => KeyRing.fromPublic(Buffer.from(p.hex, 'hex')));
    const keyInfos = [];
    for (const i of [0,1,2,3,4,5]) {
      const path = `m/0'/0'/${i}'`;
      // Just making sure that we can derive expected key from the master.
      const hd = master.derivePath(path);
      assert.bufferEqual(rings[i].publicKey, hd.publicKey);
      
      // usually `PSBT.update` depends on `WalletKey` for setting bip32 path.
      // since bip44 style is the only path the wallet copes with.
      // So this time we are going to set KeyOriginInfo manually to mimic the
      // wallet for this test.
      const fp = hash160.digest(master.publicKey);
      const fingerPrint = fp.readUInt32BE(0, true);
      keyInfos.push([hd.publicKey, KeyOriginInfo.fromOptions({fingerPrint, path})]);
    }

    psbt.inputs[0].nonWitnessUTXO = prevtx2;
    psbt.inputs[1].witnessUTXO = prevtx1.outputs[1];
    psbt.inputs[0].redeem = redeem1;
    psbt.inputs[1].redeem = redeem2; // witness program
    psbt.inputs[1].witness = witness1;
    psbt.update(rings);
    // set dummies
    psbt.inputs[0].keyInfo.set(keyInfos[0][0], keyInfos[0][1]);
    psbt.inputs[0].keyInfo.set(keyInfos[1][0], keyInfos[1][1]);
    psbt.inputs[1].keyInfo.set(keyInfos[2][0], keyInfos[2][1]);
    psbt.inputs[1].keyInfo.set(keyInfos[3][0], keyInfos[3][1]);
    psbt.outputs[0].keyInfo.set(keyInfos[4][0], keyInfos[4][1]);
    psbt.outputs[1].keyInfo.set(keyInfos[5][0], keyInfos[5][1]);

    expected = PSBT.fromRaw(d.psbt2, 'base64');
    assertPSBTEqual(psbt, expected);
    
    // change sighash
    for (const i in psbt.inputs) {
      psbt.inputs[i].sighash = 1;
    }
    expected = PSBT.fromRaw(d.psbt3, 'base64');
    assertPSBTEqual(psbt, expected);

    const psbttmp = psbt.clone(); // for second signer

    // signer1
    const privkey7 = KeyRing.fromSecret(d.key7.wif);
    const privkey8 = KeyRing.fromSecret(d.key8.wif);
    // psbt.update([privkey7, privkey8]);
    psbt.sign([privkey7, privkey8]);
    expected = PSBT.fromRaw(d.psbt4, 'base64');
    assertPSBTEqual(psbt, expected);

    // signer2
    const privkey9 = KeyRing.fromSecret(d.key9.wif);
    const privkey10 = KeyRing.fromSecret(d.key10.wif);
    expected = PSBT.fromRaw(d.psbt5, 'base64');
    psbttmp.sign([privkey9, privkey10]);
    assertPSBTEqual(psbttmp, expected);

    // combiner
    const psbtCombined1 = psbt.combine(psbttmp);
    const psbtCombined2 = psbttmp.combine(psbt);
    expected = PSBT.fromRaw(d.psbtcombined, 'base64');
    assertPSBTEqual(psbtCombined1, expected);
    assertPSBTEqual(psbtCombined2, expected);

    // finalizer
    psbt.finalize();
    expected = PSBT.fromRaw(d.psbtfinalized, 'base64');
    assertPSBTEqual(psbt, expected);

    // extractor
    const tx = psbt.toTX();
    expected = TX.fromRaw(d.txextracted, 'hex');
    assert.strictEqual(tx.txid(), expected.txid());
    assert.strictEqual(tx.wtxid(), expected.wtxid());
   /* eslint-enable */
  });

  it('can combine psbt with unknown KV-Map correctly', () => {
    const psbt1 = PSBT.fromRaw(data.psbtUnknown1, 'base64');
    const psbt2 = PSBT.fromRaw(data.psbtUnknown2, 'base64');
    let expected = PSBT.fromRaw(data.psbtUnknown3, 'base64');
    let combined = psbt1.combine(psbt2);
    assertPSBTEqual(combined, expected);

    // Even after (de)serialization.
    expected = PSBT.fromRaw(expected.toRaw());
    combined = PSBT.fromRaw(combined.toRaw());
    assertPSBTEqual(combined, expected);
  });
});

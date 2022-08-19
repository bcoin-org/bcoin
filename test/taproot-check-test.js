/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const Address = require('../lib/primitives/address');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const Output = require('../lib/primitives/output');
const Script = require('../lib/script/script');
const Taproot = require('../lib/script/taproot');
const common = require('../lib/script/common');
const schnorr = require('bcrypto/lib/schnorr');
const random = require('bcrypto/lib/random');
const {taggedHash} = require('../lib/utils');
const consensus = require('../lib/protocol/consensus');
const opcodes = Script.opcodes;

// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#Test_vectors
const {
  scriptPubKey
} = require('./data/bip341-wallet-test-vectors.json');

// Create a BIP340 Schnorr keypair
const priv = schnorr.privateKeyGenerate();
const pub = schnorr.publicKeyCreate(priv);

// Error Messages
const ERR_EMPTY_WITNESS = { message: 'WITNESS_PROGRAM_WITNESS_EMPTY'};
const ERR_SIG_SCHNORR = { message: 'TAPROOT_INVALID_SIG' };
const ERR_CONTROLBLOCK_SIZE = { message: 'TAPROOT_WRONG_CONTROL_SIZE' };
const ERR_WITNESS_PROGRAM_MISMATCH = { message: 'WITNESS_PROGRAM_MISMATCH' };
const ERR_STACK_SIZE = { message: /STACK_SIZE/g };
const ERR_SIG_SCHNORR_SIZE = {message: 'SCHNORR_SIG_SIZE' };

describe('Taproot Check', function() {
  describe('Key spend', function() {
    // Create a pay-to-taproot key-spend UTXO
    const keyspendUTXO = new Coin();
    keyspendUTXO.hash = random.randomBytes(32);
    keyspendUTXO.index = 0;
    keyspendUTXO.script = Script.fromProgram(1, pub);
    keyspendUTXO.value = 1e8;

    // Sign 1-in 1-out taproot key-spend MTX
    function signMTX(mtx) {
      const hash = mtx.signatureHashTaproot(
        0,                    // input index
        keyspendUTXO.value,   // input value
        0,                    // SIGHASH_ALL
        [keyspendUTXO],       // coins
        0xffffffff,           // codeseparator position
      );
      const sig = schnorr.sign(hash, priv);
      mtx.inputs[0].witness.items[0] = sig;
    }

    it('should have valid signature', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);
      assert(mtx.verify());
    });

    it('should have empty signature', () => {
      const mtx = new MTX();
      mtx.addCoin(keyspendUTXO);

      // No witness to sign transaction
      assert.throws(
        () => mtx.check(),
        ERR_EMPTY_WITNESS
      );
    });

    it('should have invalid schnorr signature size', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({ value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);

      mtx.inputs[0].witness.items[0] = mtx.inputs[0].witness.items[0].slice(0, -1);

      assert.throws(
        () => mtx.check(),
        ERR_SIG_SCHNORR_SIZE
      );
    });

    it('should have invalid signature', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(keyspendUTXO);

      signMTX(mtx);

      // Malleate signature by flipping a bit
      mtx.inputs[0].witness.items[0][0] ^= 0x01;

      assert.throws(
        () => mtx.check(),
        ERR_SIG_SCHNORR
      );
    });
  });

  describe('Script spend', function() {
    // Simple script that requires no signing
    const script = Script.fromString('OP_1');
    const tapLeaf = Buffer.from([
        0xc0,   // leaf version
        0x01,   // script size
        0x51    // OP_1
    ]);

    // Construct tapscript tree (with only one leaf)
    const k0 = taggedHash.TapLeafHash.digest(tapLeaf);
    const tapTweak = Buffer.alloc(64);
    pub.copy(tapTweak, 0);
    k0.copy(tapTweak, 32);
    const t = taggedHash.TapTweakHash.digest(tapTweak);
    const [tweaked, odd] = schnorr.publicKeyTweakSum(pub, t);

    // Construct control block from 1-leaf tree
    const controlBlock = Buffer.alloc(33);
    controlBlock[0] = 0xc0 + (odd ? 1 : 0);
    pub.copy(controlBlock, 1);

    // Create a pay-to-taproot script-spend UTXO
    const scriptspendUTXO = new Coin();
    scriptspendUTXO.hash = random.randomBytes(32);
    scriptspendUTXO.index = 0;
    scriptspendUTXO.script = Script.fromProgram(1, tweaked);
    scriptspendUTXO.value = 1e8;

    it('should have valid tapscript', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);

      mtx.check();
      assert(mtx.verify());
      assert(mtx.hasStandardWitness(mtx.view));
    });

    it('should be non-standard with annex', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);
      mtx.inputs[0].witness.push(Buffer.from([0x50])); // annex

      mtx.check();
      assert(mtx.verify());
      assert(!mtx.hasStandardWitness(mtx.view));
    });

    it('should have invalid control block', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      mtx.inputs[0].witness.push(script.toRaw());
      // Content of invalid control block doesn't matter
      const invalid = Buffer.alloc(controlBlock.length + 1);
      mtx.inputs[0].witness.push(invalid);

      assert.throws(
        () => mtx.check(),
        ERR_CONTROLBLOCK_SIZE
      );
    });

    it('should not match witness program', () => {
      const mtx = new MTX();
      mtx.outputs.push(new Output({value: 1e8 - 10000 }));
      mtx.addCoin(scriptspendUTXO);

      const script = Script.fromString('OP_2');

      mtx.inputs[0].witness.push(script.toRaw());
      mtx.inputs[0].witness.push(controlBlock);

      assert.throws(
        () => mtx.check(),
        ERR_WITNESS_PROGRAM_MISMATCH
      );
    });

    for (const NUM of [999, 1000]) {
      it(`should have ${NUM === 1000 ? 'invalid' : 'valid' } tapscript with ${NUM} signatures`, () => {
        const script = new Script();
        for (let i = 0; i < NUM; i++) {
          script.pushData(pub);
          script.pushOp(opcodes.OP_CHECKSIGVERIFY);
        }
        script.pushOp(opcodes.OP_1);
        script.compile();
        const raw = script.toRaw();

        const scriptSize = script.getVarSize();
        let tapLeaf = bio.write(scriptSize + 1);
        tapLeaf.writeU8(0xc0); // leaf version
        tapLeaf.writeVarBytes(raw);
        tapLeaf = tapLeaf.render();

        // Construct tapscript tree (with only one leaf)
        const k0 = taggedHash.TapLeafHash.digest(tapLeaf);
        const tapTweak = Buffer.alloc(64);
        pub.copy(tapTweak, 0);
        k0.copy(tapTweak, 32);
        const t = taggedHash.TapTweakHash.digest(tapTweak);
        const [tweaked, odd] = schnorr.publicKeyTweakSum(pub, t);

        // Construct control block from 1-leaf tree
        const controlBlock = Buffer.alloc(33);
        controlBlock[0] = 0xc0 + (odd ? 1 : 0);
        pub.copy(controlBlock, 1);

        // Create money for us to spend with this tapscript
        const utxo = new Coin();
        utxo.hash = random.randomBytes(32);
        utxo.index = 0;
        utxo.script = Script.fromProgram(1, tweaked);
        utxo.value = 1e8;

        // Spend the UTXO with our tapscript in a new TX
        const mtx = new MTX();
        mtx.outputs.push(new Output({value: 1e8 - 10000 }));
        mtx.addCoin(utxo);

        for (let i = 0; i < NUM; i++) {
          mtx.inputs[0].witness.push(Buffer.alloc(0));
        }

        mtx.inputs[0].witness.push(script.toRaw());
        mtx.inputs[0].witness.push(controlBlock);

        const hash = mtx.signatureHashTaproot(
          utxo.index,           // input index
          utxo.value,           // input value
          0,                    // SIGHASH_ALL
          [utxo],               // coins
          0xffffffff,           // codeseparator position
        );
        const sig = schnorr.sign(hash, priv);

        for (let i = 0; i < NUM; i++) {
          mtx.inputs[0].witness.items[i] = sig;
        }

        if (NUM >= consensus.MAX_SCRIPT_STACK) {
          assert.throws(
            () => mtx.check(),
            ERR_STACK_SIZE
          );
        } else {
          // Max script size does not apply to taproot
          assert(raw.length > consensus.MAX_SCRIPT_SIZE);

          mtx.check();
          assert(mtx.verify());
        }
      });
    }
  });
});

describe('Helper Functions', () => {
  it('taprootTreeHelper should produce tree root', () => {
    /*
      The outputs for the taproot tree helper function are compared against the results
      produced by the bitcoin core implementation.
    */

    const b = new Script({ raw: Buffer.from('b') });
    const c = new Script({ raw: Buffer.from('c') });
    const d = new Script({ raw: Buffer.from('d') });
    const f = new Script({ raw: Buffer.from('f') });
    const g = new Script({ raw: Buffer.from('g') });

    assert.equal(
      Taproot.taprootTreeHelper([]),
      null,
      'empty'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT)]),
      Buffer.from('c1b5bd5af873b3cf6e5a90ed7dfa03da09ad4c4f61aedb4357c87f13244d0d44', 'hex'),
      '1 leaf'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(b, 194)]),
      Buffer.from('06abb1a7f74bbb1030c8385a757352d4bde36743c4ba1eab734c9b8441e10b93', 'hex'),
      'diff leaf version'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(c, common.LEAF_VERSION_TAPSCRIPT)]),
      Buffer.from('993e66f0dc536073d5a2c5989267bc8762045303b91c027bf33666565a85f270', 'hex'),
      'diff code'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([[[[[new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT)]]]]]),
      Buffer.from('c1b5bd5af873b3cf6e5a90ed7dfa03da09ad4c4f61aedb4357c87f13244d0d44', 'hex'),
      'deep leaf'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT)]),
      Buffer.from('12991d5d42735f679bb1a24a4026f4a6e4fbe49612e2b944f26ab93198253912', 'hex'),
      '2 same leaves'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(c, common.LEAF_VERSION_TAPSCRIPT)]),
      Buffer.from('5314984f24ab08113d5790636c6c7fb8a003e60b50e5b600b62e97d04133e4a5', 'hex'),
      '2 diff leaves'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT), [new Taproot.TapLeaf(c, common.LEAF_VERSION_TAPSCRIPT)], new Taproot.TapLeaf(d, common.LEAF_VERSION_TAPSCRIPT), [new Taproot.TapLeaf(f, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(g, common.LEAF_VERSION_TAPSCRIPT)]]),
      Buffer.from('7d06227ec4d4dc84ec46a62481f86cea3466d2479184e5dc17145976bf361aef', 'hex'),
      'multiple levels'
    );

    assert.bufferEqual(
      Taproot.taprootTreeHelper([[new Taproot.TapLeaf(b, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(c, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(d, common.LEAF_VERSION_TAPSCRIPT)], [new Taproot.TapLeaf(f, common.LEAF_VERSION_TAPSCRIPT), new Taproot.TapLeaf(g, common.LEAF_VERSION_TAPSCRIPT)]]),
      Buffer.from('eab7f3ca183c40faed41641c972acf02cfaa537e124b2f3806b5323b84386426', 'hex'),
      'tree structure'
    );
  });

  describe('BIP341 test vectors', function() {
    describe('scriptPubKey', function() {
      // Conform test vectors from BIP341 json file
      function conformScriptTree (scriptTree) {
        if (!scriptTree)
          return [];

        if (Array.isArray(scriptTree))
          return scriptTree.map(x => conformScriptTree(x));

        return [
          new Taproot.TapLeaf(Script.fromRaw(scriptTree.script, 'hex'), scriptTree.leafVersion)
        ];
      }

      for (const test of scriptPubKey) {
        it(test.expected.bip350Address, () => {
          const {given, intermediary, expected} = test;
          const tree = conformScriptTree(given.scriptTree);

          // Test taproot tree helper
          const treeRoot = Taproot.taprootTreeHelper(tree);
          assert.strictEqual(treeRoot? treeRoot.toString('hex'):null, intermediary.merkleRoot);

          // Test taprootCommitment()
          const tweak = Taproot.taprootCommitment(Buffer.from(given.internalPubkey, 'hex'), treeRoot);
          assert.strictEqual(tweak.toString('hex'), intermediary.tweak);

          // Test bcrypto schnorr.publicKeyTweakCheck()
          if (expected.scriptPathControlBlocks) {
            for (const cb of expected.scriptPathControlBlocks) {
              assert(
                schnorr.publicKeyTweakCheck(
                  Buffer.from(given.internalPubkey, 'hex'),
                  Buffer.from(intermediary.tweak, 'hex'),
                  Buffer.from(intermediary.tweakedPubkey, 'hex'),
                  Boolean(parseInt(cb.slice(0, 2), 16) & 1)
                )
              );
            }
          }

          // Test bech32m
          assert.strictEqual(
            Address.fromScript(Script.fromRaw(expected.scriptPubKey, 'hex')).toString(),
            expected.bip350Address
          );
        });
      }
    });
  });
});

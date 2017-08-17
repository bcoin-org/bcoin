/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Script = require('../lib/script/script');
const Witness = require('../lib/script/witness');
const Stack = require('../lib/script/stack');
const TX = require('../lib/primitives/tx');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const opcodes = Script.opcodes;

const scripts = require('./data/script-tests.json');

function isSuccess(stack) {
  if (stack.length === 0)
    return false;

  if (!stack.bool(-1))
    return false;

  return true;
}

function parseScriptTest(data) {
  const witArr = Array.isArray(data[0]) ? data.shift() : [];
  const inpHex = data[0];
  const outHex = data[1];
  const names = data[2] || 'NONE';
  const expected = data[3];
  let comments = data[4];

  if (!comments)
    comments = outHex.slice(0, 60);

  comments += ` (${expected})`;

  let value = 0;
  if (witArr.length > 0)
    value = util.fromFloat(witArr.pop(), 8);

  const witness = Witness.fromString(witArr);
  const input = Script.fromString(inpHex);
  const output = Script.fromString(outHex);

  let flags = 0;
  for (const name of names.split(',')) {
    const flag = Script.flags[`VERIFY_${name}`];

    if (flag == null)
      throw new Error(`Unknown flag: ${name}.`);

    flags |= flag;
  }

  return {
    witness: witness,
    input: input,
    output: output,
    value: value,
    flags: flags,
    expected: expected,
    comments: comments
  };
}

describe('Script', function() {
  it('should encode/decode script', () => {
    const src = Buffer.from(''
      + '20'
      + '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '20'
      + '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
      + 'ac',
      'hex');

    const decoded = Script.fromRaw(src);
    assert.strictEqual(decoded.code.length, 3);
    assert.strictEqual(decoded.code[0].data.toString('hex'),
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    assert.strictEqual(decoded.code[1].data.toString('hex'),
      '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
    assert.strictEqual(decoded.code[2].value, opcodes.OP_CHECKSIG);

    const dst = decoded.toRaw();
    assert.bufferEqual(dst, src);
  });

  it('should encode/decode numbers', () => {
    const script = [0, 0x51, 0x52, 0x60];
    const encoded = Script.fromArray(script).raw;
    const decoded = Script(encoded).toArray();
    assert.deepStrictEqual(decoded, script);
  });

  it('should recognize a P2SH output', () => {
    const hex = 'a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87';
    const decoded = Script.fromRaw(hex, 'hex');
    assert(decoded.isScripthash());
  });

  it('should recognize a Null Data output', () => {
    const hex = '6a28590c080112220a1b353930632e6f7267282a5f'
      + '5e294f7665726c6179404f7261636c65103b1a010c';
    const decoded = Script.fromRaw(hex, 'hex');
    assert(decoded.isNulldata());
  });

  it('should handle if statements correctly', () => {
    {
      const input = new Script([opcodes.OP_1, opcodes.OP_2]);

      const output = new Script([
        opcodes.OP_2,
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_3,
        opcodes.OP_ELSE,
        opcodes.OP_4,
        opcodes.OP_ENDIF,
        opcodes.OP_5
      ]);

      const stack = new Stack();

      input.execute(stack);
      output.execute(stack);

      assert.deepEqual(stack.items, [[1], [3], [5]]);
    }

    {
      const input = new Script([opcodes.OP_1, opcodes.OP_2]);

      const output = new Script([
        opcodes.OP_9,
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_3,
        opcodes.OP_ELSE,
        opcodes.OP_4,
        opcodes.OP_ENDIF,
        opcodes.OP_5
      ]);

      const stack = new Stack();

      input.execute(stack);
      output.execute(stack);

      assert.deepEqual(stack.items, [[1], [4], [5]]);
    }

    {
      const input = new Script([opcodes.OP_1, opcodes.OP_2]);

      const output = new Script([
        opcodes.OP_2,
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_3,
        opcodes.OP_ENDIF,
        opcodes.OP_5
      ]);

      const stack = new Stack();

      input.execute(stack);
      output.execute(stack);

      assert.deepEqual(stack.items, [[1], [3], [5]]);
    }

    {
      const input = new Script([opcodes.OP_1, opcodes.OP_2]);

      const output = new Script([
        opcodes.OP_9,
        opcodes.OP_EQUAL,
        opcodes.OP_IF,
        opcodes.OP_3,
        opcodes.OP_ENDIF,
        opcodes.OP_5
      ]);

      const stack = new Stack();

      input.execute(stack);
      output.execute(stack);

      assert.deepEqual(stack.items, [[1], [5]]);
    }

    {
      const input = new Script([opcodes.OP_1, opcodes.OP_2]);

      const output = new Script([
        opcodes.OP_9,
        opcodes.OP_EQUAL,
        opcodes.OP_NOTIF,
        opcodes.OP_3,
        opcodes.OP_ENDIF,
        opcodes.OP_5
      ]);

      const stack = new Stack();

      input.execute(stack);
      output.execute(stack);

      assert.deepEqual(stack.items, [[1], [3], [5]]);
    }
  });

  it('should handle CScriptNums correctly', () => {
    const input = new Script([
      Buffer.from('ffffff7f', 'hex'),
      opcodes.OP_NEGATE,
      opcodes.OP_DUP,
      opcodes.OP_ADD
    ]);

    const output = new Script([
      Buffer.from('feffffff80', 'hex'),
      opcodes.OP_EQUAL
    ]);

    const stack = new Stack();

    input.execute(stack);
    output.execute(stack);

    assert(isSuccess(stack));
  });

  it('should handle CScriptNums correctly', () => {
    const input = new Script([
      opcodes.OP_11,
      opcodes.OP_10,
      opcodes.OP_1,
      opcodes.OP_ADD
    ]);

    const output = new Script([
      opcodes.OP_NUMNOTEQUAL,
      opcodes.OP_NOT
    ]);

    const stack = new Stack();

    input.execute(stack);
    output.execute(stack);

    assert(isSuccess(stack));
  });

  it('should handle OP_ROLL correctly', () => {
    const input = new Script([
      Buffer.from([0x16]),
      Buffer.from([0x15]),
      Buffer.from([0x14])
    ]);

    const output = new Script([
      opcodes.OP_0,
      opcodes.OP_ROLL,
      Buffer.from([0x14]),
      opcodes.OP_EQUALVERIFY,
      opcodes.OP_DEPTH,
      opcodes.OP_2,
      opcodes.OP_EQUAL
    ]);

    const stack = new Stack();

    input.execute(stack);
    output.execute(stack);

    assert(isSuccess(stack));
  });

  for (const data of scripts) {
    if (data.length === 1)
      continue;

    const test = parseScriptTest(data);
    const {witness, input, output} = test;
    const {value, flags} = test;
    const {expected, comments} = test;

    for (const noCache of [false, true]) {
      const suffix = noCache ? 'without cache' : 'with cache';

      it(`should handle script test ${suffix}:${comments}`, () => {
        // Funding transaction.
        const prev = new TX({
          version: 1,
          inputs: [{
            prevout: {
              hash: encoding.NULL_HASH,
              index: 0xffffffff
            },
            script: [opcodes.OP_0, opcodes.OP_0],
            witness: [],
            sequence: 0xffffffff
          }],
          outputs: [{
            script: output,
            value: value
          }],
          locktime: 0
        });

        // Spending transaction.
        const tx = new TX({
          version: 1,
          inputs: [{
            prevout: {
              hash: prev.hash('hex'),
              index: 0
            },
            script: input,
            witness: witness,
            sequence: 0xffffffff
          }],
          outputs: [{
            script: [],
            value: value
          }],
          locktime: 0
        });

        if (noCache) {
          prev.refresh();
          tx.refresh();
        }

        let err;
        try {
          Script.verify(input, witness, output, tx, 0, value, flags);
        } catch (e) {
          err = e;
        }

        if (expected !== 'OK') {
          assert.typeOf(err, 'error');
          assert.strictEqual(err.code, expected);
          return;
        }

        assert.ifError(err);
      });
    }
  }
});

/* eslint-disable quotes */
/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const HD = require('../lib/hd');
const assert = require('bsert');

const parsable = [
  {
    "input": "d34db33f/44h/0'/0'",
    "expected": "d34db33f/44h/0h/0h"
  },
  {
    "input": "d34db33f",
    "expected": "d34db33f"
  },
  {
    "input": "d34db33f/44/0'/0h",
    "expected": "d34db33f/44/0h/0h"
  },
  {
    "input": "d34db33f/44/0'/0",
    "expected": "d34db33f/44/0h/0"
  },
  {
    "input": "d34db33f/44h/0/0",
    "expected": "d34db33f/44h/0/0"
  },
  {
    "input": "d34db33f/44'/0h/0",
    "expected": "d34db33f/44h/0h/0"
  },
  {
    "input": "d34db33f/44'/0'/0'",
    "expected": "d34db33f/44h/0h/0h"
  },
  {
    "input": "deadbeef/1/2'/3/4'",
    "expected": "deadbeef/1/2h/3/4h"
  },
  {
    "input": "ffffffff/13'",
    "expected": "ffffffff/13h"
  },
  {
    "input": "00000000/111'/222",
    "expected": "00000000/111h/222"
  },
  {
    "input": "e7dd1c50/48'/1'/40'/1'",
    "expected": "e7dd1c50/48h/1h/40h/1h"
  }
];

const unparsable = {
  "strings": [
    {
      "input": "d34db33f/2147483648/0'/0'",
      "error": "Key path value 2147483648 is out of range"
    },
    {
      "input": "d34db33f/42949672961/0'/0'",
      "error": "Path index too large."
    },
    {
      "input": "d34db33f/",
      "error": "Path index is non-numeric."
    },
    {
      "input": "zzzzzzzz",
      "error": "Fingerprint zzzzzzzz is not hex"
    }
  ],
  "jsons": [
    {
      "input": {
        "fingerPrint": "aaaaaaaaa",
        "path": ""
      },
      "error": "Expected 8 characters fingerprint, found 9 instead"
    },
    {
      "input": {
        "fingerPrint": 3545084735,
        "path": "44h/0h/0h"
      },
      "error": "Invalid path root." // path string should start with m for fromJSON
    },
    {
      "input": {
        "fingerPrint": 3545084735,
        "path": [42949672961, 2147483648, 2147483648]
      },
      "error": "All path indices must be uint32"
    },
    {
      "input": {
        "fingerPrint": 42949672961,
        "path": [42949672961, 2147483648, 2147483648]
      },
      "error": "Fingerprint must be uint32"
    }
  ]
};

describe('KeyOriginInfo', function () {
  for (const data of parsable) {
    it(`should create a KeyOriginInfo object for ${data.input} `, () => {
      const keyOriginInfo = HD.KeyOriginInfo.fromString(data.input);
      assert.strictEqual(keyOriginInfo.toString(), data.expected);
    });
  }

  for (const data of parsable) {
    it(`should create a KeyOriginInfo object from raw data for ${data.input}`, () => {
      const keyOriginInfo1 = HD.KeyOriginInfo.fromString(data.input);
      const keyOriginInfo2 = HD.KeyOriginInfo.fromRaw(keyOriginInfo1.toRaw());
      assert.deepStrictEqual(keyOriginInfo2.toString(), data.expected);
    });
  }

  for (const data of parsable) {
    it(`should correctly validate two equal KeyOriginInfo objects for ${data.input}`, () => {
      const keyOriginInfo1 = HD.KeyOriginInfo.fromString(data.input);
      const keyOriginInfo2 = HD.KeyOriginInfo.fromString(data.input);
      assert.strictEqual(keyOriginInfo1.equals(keyOriginInfo2), true);
    });
  }

  for (const data of parsable) {
    it(`should create a KeyOriginInfo object from a JSON object for ${data.input}`, () => {
      const keyOriginInfo1 = HD.KeyOriginInfo.fromString(data.input);
      const keyOriginInfo2 = HD.KeyOriginInfo.fromJSON(keyOriginInfo1.toJSON());
      const keyOriginInfo3 = HD.KeyOriginInfo.fromJSON({
        fingerPrint: keyOriginInfo1.fingerPrint,
        path: keyOriginInfo1.path
      });
      assert.deepStrictEqual(keyOriginInfo2.toString(), data.expected);
      assert.deepStrictEqual(keyOriginInfo3.toString(), data.expected);
    });
  }

  for (const data of parsable) {
    it(`should create a KeyOriginInfo object from options object for ${data.input}`, () => {
      const keyOriginInfo1 = HD.KeyOriginInfo.fromString(data.input);
      const keyOriginInfo2 = HD.KeyOriginInfo.fromOptions({
        fingerPrint: keyOriginInfo1.fingerPrint,
        path: keyOriginInfo1.path
      });
      assert.deepStrictEqual(keyOriginInfo2.toString(), data.expected);
    });
  }

  for (const data of parsable) {
    it(`should clone a KeyOriginInfo object for ${data.input}`, () => {
      const keyOriginInfo1 = HD.KeyOriginInfo.fromString(data.input);
      const keyOriginInfo2 = keyOriginInfo1.clone();
      assert.strictEqual(keyOriginInfo1.equals(keyOriginInfo2), true);
    });
  }

  for (const data of unparsable.strings) {
    it(`should throw "${data.error}" for ${data.input} when creating KeyOriginInfo object from string `, () => {
      assert.throws(
        () => {
          HD.KeyOriginInfo.fromString(data.input);
        },
        {
          message: data.error
        }
      );
    });
  }

  for (const data of unparsable.jsons) {
    it(`should throw "${data.error}" for json: {fingerPrint: ${data.input.fingerPrint}, path: [${data.input.path}]} when creating KeyOriginInfo object from json `, () => {
      assert.throws(
        () => {
          HD.KeyOriginInfo.fromJSON(data.input);
        },
        {
          message: data.error
        }
      );
    });
  }
});

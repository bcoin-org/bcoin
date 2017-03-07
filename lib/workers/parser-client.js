/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var packets = require('./packets');
var ServerParser = require('./parser');
var MTX = require('../primitives/mtx');
var TX = require('../primitives/tx');
var KeyRing = require('../primitives/keyring');
var CoinView = require('../coins/coinview');

/**
 * Parser
 * @alias module:workers.ParserClient
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  ServerParser.call(this);
}

util.inherits(Parser, ServerParser);

Parser.prototype.parsePacket = function parsePacket(header, data) {
  switch (header.cmd) {
    case packets.types.EVENT:
      return packets.EventPacket.fromRaw(data);
    case packets.types.LOG:
      return packets.LogPacket.fromRaw(data);
    case packets.types.ERROR:
      return packets.ErrorPacket.fromRaw(data);
    case packets.types.VERIFY:
      return packets.VerifyPacket.fromRaw(TX, CoinView, data);
    case packets.types.SIGN:
      return packets.SignPacket.fromRaw(MTX, KeyRing, data);
    case packets.types.VERIFYINPUT:
      return packets.VerifyInputPacket.fromRaw(TX, data);
    case packets.types.SIGNINPUT:
      return packets.SignInputPacket.fromRaw(MTX, KeyRing, data);
    case packets.types.ECVERIFY:
      return packets.ECVerifyPacket.fromRaw(data);
    case packets.types.ECSIGN:
      return packets.ECSignPacket.fromRaw(data);
    case packets.types.MINE:
      return packets.MinePacket.fromRaw(data);
    case packets.types.SCRYPT:
      return packets.ScryptPacket.fromRaw(data);
    default:
      throw new Error('Unknown packet.');
  }
};

/*
 * Expose
 */

module.exports = Parser;

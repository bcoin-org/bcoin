/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var BufferWriter = require('../utils/writer');

/**
 * Framer
 * @constructor
 */

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();

  EventEmitter.call(this);
}

util.inherits(Framer, EventEmitter);

Framer.prototype.packet = function _packet(packet) {
  var bw = new BufferWriter();
  var data;

  bw.writeU32(packet.id);
  bw.writeU8(packet.cmd);
  bw.seek(4);

  packet.toWriter(bw);

  bw.writeU8(0x0a);

  data = bw.render();
  data.writeUInt32LE(data.length - 10, 5, true);

  return data;
};

/*
 * Expose
 */

module.exports = Framer;

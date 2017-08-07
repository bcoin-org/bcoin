/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const StaticWriter = require('../utils/staticwriter');

/**
 * Framer
 * @alias module:workers.Framer
 * @constructor
 */

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();
}

Framer.prototype.packet = function packet(payload) {
  const size = 10 + payload.getSize();
  const bw = new StaticWriter(size);

  bw.writeU32(payload.id);
  bw.writeU8(payload.cmd);
  bw.seek(4);

  payload.toWriter(bw);

  bw.writeU8(0x0a);

  const msg = bw.render();
  msg.writeUInt32LE(msg.length - 10, 5, true);

  return msg;
};

/*
 * Expose
 */

module.exports = Framer;

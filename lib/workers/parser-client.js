/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var ServerParser = require('./parser');
var MTX = require('../primitives/mtx');
var TX = require('../primitives/tx');
var KeyRing = require('../primitives/keyring');

/**
 * Parser
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  ServerParser.call(this);

  this.TX = TX;
  this.MTX = MTX;
  this.KeyRing = KeyRing;
}

util.inherits(Parser, ServerParser);

/*
 * Expose
 */

module.exports = Parser;

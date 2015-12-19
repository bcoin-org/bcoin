/**
 * protocol/index.js - bitcoin protocol for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var protocol = exports;

protocol.constants = require('./constants');
protocol.framer = require('./framer');
protocol.parser = require('./parser');
protocol.network = require('./network');

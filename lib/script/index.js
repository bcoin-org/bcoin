/*!
 * script/index.js - bitcoin scripting for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module script
 */

exports.common = require('./common');
exports.Opcode = require('./opcode');
exports.Program = require('./program');
exports.Script = require('./script');
exports.ScriptError = require('./scripterror');
exports.ScriptNum = require('./scriptnum');
exports.sigcache = require('./sigcache');
exports.Stack = require('./stack');
exports.Witness = require('./witness');

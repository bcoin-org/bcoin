var protocol = exports;

protocol.constants = require('./constants');
protocol.framer = require('./framer');
protocol.parser = require('./parser');

if (protocol.constants.isTestnet) {
    protocol.preload = require('./preload-test');
} else {
    protocol.preload = require('./preload');
}

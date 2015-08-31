var protocol = exports;

protocol.constants = require('./constants');
protocol.framer = require('./framer');
protocol.parser = require('./parser');

if (process.env.TEST) {
    protocol.preload = require('./preload-test');
} else {
    protocol.preload = require('./preload');
}

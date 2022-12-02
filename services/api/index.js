'use strict';

const EventEmitter = require('events');

const cookieParser = require('cookie-parser');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');

const Router = require('./routes');

class Api extends EventEmitter {
  constructor(options) {
    super();

    this.app = express();


    options.app = this.app;
    options.logger = this.logger;

    const router = new Router(options);

    this.setting();
    router.init();
    this.handleNext();
  }

  setting() {
    this.app.set('query parser', 'simple');
    this.app.set('case sensitive routing', true);
    this.app.set('jsonp callback name', 'callback');
    this.app.set('strict routing', true);
    this.app.set('trust proxy', true);
    this.app.disable('x-powered-by');

    this.app.use(morgan('tiny', {
      stream: {
        write: (line) => console.log(line)
      }
    }));
    this.app.use(helmet());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: false }));
    this.app.use(cookieParser());
  }

  handleNext() {
    this.app.use((data, req, res, next) => {
      if (!data || !data.success) {
        res.status(400).json('error');
        return;
      }

      this.emit('data', data);
      res.status(200).json(data.message);
    });
  }

  start() {
    this.app.listen(30001, '127.0.0.1', () => {
      console.log('Api listening at %d', 30001);
    });
  }
}

module.exports = Api;

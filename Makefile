all:
	@npm run browserify
	@npm run uglify
	@cp -f lib/workers/worker-browser.js browser/bcoin-worker.js

clean:
	@npm run clean

docs:
	@npm run docs

test:
	@npm test

.PHONY: all clean docs test

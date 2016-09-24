all:
	@npm run browserify
	@npm run uglify

clean:
	@npm run clean

test:
	@npm test

.PHONY: all clean test

all:
	@npm run browserify

clean:
	@npm run clean

test:
	@npm test

.PHONY: all clean test

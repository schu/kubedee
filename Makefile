bash_files=$(shell git ls-files --exclude-standard | xargs -I{} file --mime-type {} | awk '/.* text\/x-shellscript$$/ {gsub(":",""); print $$1}')

all: lint

.PHONY: all

lint:
	shfmt -i 2 -w $(bash_files)
	shellcheck $(bash_files)

.PHONY: lint

test:
	./tests/lint-bash $(bash_files)
	./tests/smoke-test

.PHONY: test

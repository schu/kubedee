bash_files=$(shell git ls-files --exclude-standard | xargs -I{} file --mime-type {} | awk '/.* text\/x-shellscript$$/ {gsub(":",""); print $$1}')

.PHONY: all
all: lint

.PHONY: lint
lint:
	shfmt -i 2 -w $(bash_files)
	shellcheck $(bash_files)
	./scripts/lint-bash $(bash_files)

# Makefile used for development

DUNE=dune

lib:
	$(DUNE) build @install

.PHONY: examples
examples:
	$(DUNE) exec -- examples/examples.exe

doc:
	$(DUNE) build @doc

upload_doc: doc
	git checkout gh-pages && rm -rf dev/* && cp -r _build/default/_doc/_html/argon2/* dev && \
	git add --all dev

fmt:
	$(DUNE) build @fmt --auto-promote

clean:
	$(DUNE) clean

dev:
	$(DUNE) build @all @fmt --auto-promote --watch

test:
	$(DUNE) runtest

test-promote:
	$(DUNE) runtest --auto-promote

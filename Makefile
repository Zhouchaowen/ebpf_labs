LIBBPF_DIR=./libbpf/src/

env:
	cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=. && mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.;

builder:
	docker build -t bpf-builder:latest docker/builder
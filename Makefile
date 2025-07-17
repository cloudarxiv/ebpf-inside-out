.PHONY: get-tools install clean dist-clean

get-tools:
	@mkdir -p tools
	@echo "Installing required tools..."
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "x86_64" ]; then \
		echo "Architecture: x86_64"; \
		wget 'https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc' -O tools/ecc && chmod +x tools/ecc; \
		wget 'https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli' -O tools/ecli && chmod +x tools/ecli; \
	elif [ "$$ARCH" = "aarch64" ]; then \
		echo "Architecture: arm64"; \
		wget 'https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc-aarch64' -O tools/ecc && chmod +x tools/ecc; \
		wget 'https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli-aarch64' -O tools/ecli && chmod +x tools/ecli; \
	fi
	@sudo ln -sf tools/ecc /usr/local/bin/ecc
	@sudo ln -sf tools/ecli /usr/local/bin/ecli

install-dependencies:
	@sudo apt update
	@sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm

clean:
	@find . -type f -name '*.o' -delete
	@find . -type f -name '*.json' -delete

dist-clean: clean
	@sudo rm /usr/local/bin/ecc || true
	@sudo rm /usr/local/bin/ecli || true
	@rm -rf tools
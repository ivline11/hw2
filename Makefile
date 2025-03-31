# 최소한의 Makefile 예시
# 과제 요구사항: "make" 실행 시 mac 실행 파일이 만들어져야 함.

.PHONY: all clean

all: mac

mac: src/bin/mac.rs
	cargo build --release
	cp target/release/mac .

clean:
	cargo clean
	rm -f mac

## Makefile — AES-256-GCM Amortized Protocol Variant
## Cloned from basepaper_amortization — AEAD upgraded to AES-256-GCM
## Parameters: POLY_DEGREE=512, RING_SIZE=3, LDPC 102x204 (same as base paper)
## Runs on Cooja Mote (JVM, unlimited RAM). Do NOT use TARGET=z1 here.
## Cipher: AES-256-GCM per NIST SP 800-38D (96-bit nonce, 128-bit tag, 256-bit key)

CONTIKI_PROJECT = node-sender_bp node-gateway_bp

all: $(CONTIKI_PROJECT)

# Source files - base-paper parameter versions
PROJECT_SOURCEFILES += crypto_core_bp.c crypto_core_session_bp.c

# Build for Cooja Mote (JVM - can handle full base-paper parameters)
TARGET ?= cooja

# Contiki-NG installation path
CONTIKI = /home/selfi/contiki-ng

include $(CONTIKI)/Makefile.include

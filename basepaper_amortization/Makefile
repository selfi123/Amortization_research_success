## Makefile — Base Paper Parameter Amortized Protocol
## Matches Kumari et al. parameters: POLY_DEGREE=512, RING_SIZE=3, LDPC 102x204
## Runs on Cooja Mote (JVM, unlimited RAM). Do NOT use TARGET=z1 here.

CONTIKI_PROJECT = node-sender_bp node-gateway_bp

all: $(CONTIKI_PROJECT)

# Source files - base-paper parameter versions
PROJECT_SOURCEFILES += crypto_core_bp.c crypto_core_session_bp.c

# Build for Cooja Mote (JVM - can handle full base-paper parameters)
TARGET ?= cooja

# Contiki-NG installation path
CONTIKI = /home/selfi/contiki-ng

include $(CONTIKI)/Makefile.include

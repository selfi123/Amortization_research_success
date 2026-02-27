# ============================================================
# Makefile for Amortized Lattice Protocol (Z1 Mote Target)
# Targets Zolertia Z1 mote (MSP430F2617, 8KB RAM, 92KB Flash)
# ============================================================

CONTIKI_PROJECT = node-sender_z1 node-gateway_z1
all: $(CONTIKI_PROJECT)

# Source files for cryptographic operations - Z1-specific versions
PROJECT_SOURCEFILES += crypto_core_z1.c crypto_core_session_z1.c

# Session amortization parameters are defined in crypto_core_z1.h; do NOT redefine here.


# Z1 target platform - enables memory optimizations
TARGET = z1

# Memory optimization flags for MSP430 constrained target
CFLAGS += -Os -ffunction-sections -fdata-sections -DTARGET_Z1=1

# Use FLASH for large constant tables to save precious RAM
# On MSP430, 'const' variables are placed directly in FLASH automatically
CFLAGS += -DUSE_FLASH_STORAGE=1

# Linker: strip unused sections to reduce firmware size
LDFLAGS += -Wl,--gc-sections

# Contiki-NG installation path
CONTIKI = /home/selfi/contiki-ng

# Include Contiki-NG build system
include $(CONTIKI)/Makefile.include

# Memory size check
size: $(CONTIKI_PROJECT)
	@echo "=== Z1 Mote Memory Usage Report ==="
	@msp430-size node-sender_z1.z1 node-gateway_z1.z1 2>/dev/null || echo "Use msp430-gcc toolchain"
	@echo "==================================="
	@echo "Z1 Mote Hard Limits:"
	@echo "  RAM:  8192 bytes  (8 KB)"
	@echo "  ROM:  92160 bytes (90 KB)"
	@echo "==================================="

clean-all:
	rm -f *.z1 *.o *.d *~ symbols.c symbols.h

# Help target
help:
	@echo "Post-Quantum IoT Auth Protocol - Zolertia Z1 Target"
	@echo "====================================================="
	@echo "  make             - Build for Z1 mote"
	@echo "  make size        - Show memory usage summary"
	@echo "  make clean-all   - Remove all build artifacts"
	@echo ""
	@echo "Open Cooja -> Add Motes -> Z1 Mote -> Load node-sender_z1.z1"

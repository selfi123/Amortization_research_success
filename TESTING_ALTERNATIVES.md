# Alternative Testing Methods for Ring-LWE Implementation

## Issue Summary
Cooja GUI is experiencing Java stack smashing errors unrelated to our compiled code. The error occurs during Cooja's startup, before any simulation is loaded.

## Solutions (in order of recommendation)

### ✅ Option 1: Use Cooja CSC File (Command-Line)
Create a simulation file and run Cooja headless:

```bash
# This bypasses the GUI startup issue
cd /home/selfi/contiki-ng/tools/cooja
./gradlew run --args="-nogui=/path/to/simulation.csc"
```

**Status**: Need to create simulation.csc file first

---

### ✅ Option 2: Fix Cooja GUI Issue
The stack smashing is likely due to:
1. **Fortify source protection** in libc
2. **Java native library** incompatibility

**Potential fixes**:

#### A. Disable stack protection
```bash
export _FORTIFY_SOURCE=0
cd /home/selfi/contiki-ng/tools/cooja && ./gradlew run
```

#### B. Use older/different Java version
```bash
# Check current Java
java -version  # Currently: OpenJDK 17

# Try Java 11 if available
sudo update-alternatives --config java
```

#### C. Rebuild Cooja native libraries
```bash
cd /home/selfi/contiki-ng/tools/cooja
./gradlew clean
./gradlew build
./gradlew run
```

---

### ✅ Option 3: Test with Native Build (Limited)
Our code compiles and runs on native platform:

```bash
cd /home/selfi/contiki-ng/examples/Amortization_Research

# Run test script
./test_crypto.sh
```

**Limitations**: 
- No wireless networking (would need TAP/TUN setup)
- Can verify crypto algorithms work
- Cannot test full protocol flow

---

### ✅ Option 4: Test on Real Hardware
If you have Z1 motes or similar:

```bash
make TARGET=z1
make upload-sender
make upload-gateway
```

---

### ✅ Option 5: Use Contiki-NG Docker
Isolated environment with working Cooja:

```bash
docker pull contiker/contiki-ng
docker run -it --rm -v $(pwd):/home/user/project contiker/contiki-ng
# Inside container:
cd /home/user/project
cooja
```

---

## Recommended Next Step

**Try Option 1 or Option 2A first** - they're quickest. Let me know which you'd like to try!

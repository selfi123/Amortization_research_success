#!/bin/bash
# Simple test script for Ring-LWE crypto implementation
# Tests gateway and sender in native mode

echo "=== Ring-LWE Crypto Test (Native Mode) ==="
echo ""

# Test 1: Run gateway in background
echo "[1/3] Starting gateway..."
cd /home/selfi/contiki-ng/examples/Amortization_Research
timeout 30s ./build/native/node-gateway.native > gateway.log 2>&1 &
GATEWAY_PID=$!
sleep 2

# Test 2: Run sender
echo "[2/3] Starting sender..."
timeout 25s ./build/native/node-sender.native > sender.log 2>&1
SENDER_EXIT=$?

# Wait for gateway to finish
wait $GATEWAY_PID 2>/dev/null
GATEWAY_EXIT=$?

echo "[3/3] Checking logs..."
echo ""

# Display results
echo "=== GATEWAY LOG ==="
cat gateway.log
echo ""
echo "=== SENDER LOG ==="
cat sender.log
echo ""

echo "=== TEST SUMMARY ==="
echo "Gateway exit code: $GATEWAY_EXIT"
echo "Sender exit code: $SENDER_EXIT"

if grep -q "Auth request received" gateway.log && grep -q "Auth phase" sender.log; then
    echo "✓ Communication detected"
else
    echo "✗ No communication detected (expected for native without proper networking)"
fi

echo ""
echo "NOTE: Native mode requires proper network setup (TAP/TUN)."
echo "For full testing, use Cooja simulator or real hardware."

#!/bin/bash
# Test script to verify our code changes compile successfully

cd ~/contiki-ng/examples/Amortization_Research

echo "=== Compiling node-sender.cooja ==="
make COOJA_VIB_SENSOR=0 COOJA_SERIAL=0 COOJA_BEEP=0 COOJA_IP=0 COOJA_RADIO=0 COOJA_BUTTON=0 COOJA_PIR_SENSOR=0 COOJA_LED=0 COOJA_CFS=0 COOJA_EEPROM=0 -j4 node-sender.cooja TARGET=cooja clean
make COOJA_VIB_SENSOR=0 COOJA_SERIAL=0 COOJA_BEEP=0 COOJA_IP=0 COOJA_RADIO=0 COOJA_BUTTON=0 COOJA_PIR_SENSOR=0 COOJA_LED=0 COOJA_CFS=0 COOJA_EEPROM=0 -j4 node-sender.cooja TARGET=cooja

if [ $? -eq 0 ]; then
    echo "✅ node-sender.cooja compiled successfully!"
else
    echo "❌ node-sender.cooja compilation failed!"
    exit 1
fi

echo ""
echo "=== Compiling node-gateway.cooja ==="
make COOJA_VIB_SENSOR=0 COOJA_SERIAL=0 COOJA_BEEP=0 COOJA_IP=0 COOJA_RADIO=0 COOJA_BUTTON=0 COOJA_PIR_SENSOR=0 COOJA_LED=0 COOJA_CFS=0 COOJA_EEPROM=0 -j4 node-gateway.cooja TARGET=cooja clean
make COOJA_VIB_SENSOR=0 COOJA_SERIAL=0 COOJA_BEEP=0 COOJA_IP=0 COOJA_RADIO=0 COOJA_BUTTON=0 COOJA_PIR_SENSOR=0 COOJA_LED=0 COOJA_CFS=0 COOJA_EEPROM=0 -j4 node-gateway.cooja TARGET=cooja

if [ $? -eq 0 ]; then
    echo "✅ node-gateway.cooja compiled successfully!"
else
    echo "❌ node-gateway.cooja compilation failed!"
    exit 1
fi

echo ""
echo "=== ✅ All code compiled successfully! ==="
echo "The signature verification fix is ready, but Cooja GUI is broken."

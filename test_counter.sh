#!/bin/bash
echo "Process started with PID: $$"
COUNTER=0
while true; do
    echo "Counter: $COUNTER"
    COUNTER=$((COUNTER+1))
    sleep 2
done

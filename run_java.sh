#!/bin/bash

# Compile Java program
javac Main.java

# Run Java program in background, get its PID
java Main &
JAVA_PID=$!
echo "Java program started with PID: $JAVA_PID"

# Wait a moment for JVM to fully start
sleep 2

# Create build directory and compile the C++ interceptor
mkdir -p build
cd build
cmake ..
make

# Run the deadlock interceptor with the Java PID
echo "Starting deadlock interceptor for PID: $JAVA_PID"
sudo ./deadlock-interceptor $JAVA_PID 1
ps -p $JAVA_PID

# Wait for both processes
wait $JAVA_PID

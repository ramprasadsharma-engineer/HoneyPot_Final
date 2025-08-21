#!/bin/bash
# Script to test the honeypot with simulated login attempts

TARGET="localhost"
PORT="2222"
USERNAMES=("root" "admin" "user" "oracle" "test")
PASSWORDS=("password" "123456" "admin" "root" "qwerty")

echo "Testing honeypot with simulated login attempts..."

for username in "${USERNAMES[@]}"; do
  for password in "${PASSWORDS[@]}"; do
    echo "Trying $username:$password"
    sshpass -p "$password" ssh -o StrictHostKeyChecking=no -p $PORT $username@$TARGET "ls -la; whoami; cat /etc/passwd" 2>/dev/null || echo "Login failed as expected"
    sleep 1
  done
done

echo "Test complete. Check logs for recorded activity."

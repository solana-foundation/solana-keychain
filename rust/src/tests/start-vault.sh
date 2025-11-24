#!/bin/bash

# Start Vault in dev mode
echo "Starting Vault dev server..."
vault server -dev -dev-root-token-id="root" &

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
sleep 5

# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Wait for Vault API to be available
echo "Checking Vault API availability..."
for i in {1..10}; do
    if vault status > /dev/null 2>&1; then
        echo "Vault API is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "Error: Vault API not available after 10 attempts"
        exit 1
    fi
    echo "Waiting for Vault API... ($i/10)"
    sleep 1
done

# Enable transit engine
vault secrets enable transit >/dev/null 2>&1

# Key backup file for deterministic testing
KEY_BACKUP_FILE="src/tests/vault-test-key.b64"

# Ensure backup file exists
if [ ! -f "$KEY_BACKUP_FILE" ]; then
    echo "Error: Vault key backup file not found at $KEY_BACKUP_FILE"
    echo "This file is required for deterministic testing and should be checked into the repository."
    exit 1
fi

echo "Restoring key from backup..."
vault write transit/restore/solana-test-key backup=@"$KEY_BACKUP_FILE" >/dev/null 2>&1

echo "✅ Vault dev server is running!"
#!/bin/bash
set -e

echo "Pulling latest code..."
git pull

echo "Removing old container if it exists..."
docker rm -f ajh-website || true

echo "Building and restarting with Docker Compose..."
docker-compose up -d --build

echo "Update complete"

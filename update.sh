#!/bin/bash
set -e

echo "Pulling latest code..."
git pull

echo "Building and restarting with Docker Compose..."
docker-compose up -d --build

echo "Update complete"

#!/bin/bash
set -e

echo "Pulling latest code..."
git pull

echo "Stopping and removing old containers..."
docker-compose down

echo "Building and starting fresh..."
docker-compose up -d --build

echo "Update complete"

#!/bin/bash
# Helper script to build and push multi-arch Docker images locally
# Requires: docker buildx

set -e

IMAGE_NAME="debasishtripathy1302/project-libra"
VERSION=$(date +%Y%m%d)-dev

# Initialize buildx if not already done
if ! docker buildx inspect libra-builder > /dev/null 2>&1; then
    echo "Creating new buildx builder instance..."
    docker buildx create --name libra-builder --use
    docker buildx inspect --bootstrap
fi

echo "Building and pushing $IMAGE_NAME:$VERSION for linux/amd64 and linux/arm64..."

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag $IMAGE_NAME:latest \
  --tag $IMAGE_NAME:$VERSION \
  --push \
  .

echo "Successfully pushed multi-arch images!"

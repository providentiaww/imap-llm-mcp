#!/bin/bash
# Deploy Risa triage cron job to aequor
# Usage: ./deploy.sh [--dry-run]
set -e

NAMESPACE="risa"
REGISTRY="provrepo.fxbg.providentiaworldwide.com:5000"
IMAGE="risa-triage"
TAG="${1:-latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRON_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Risa Triage Cron Deploy ==="
echo "Registry: $REGISTRY"
echo "Image: $IMAGE:$TAG"
echo "Namespace: $NAMESPACE"

# Step 1: Build arm64 image
echo -e "\n--- Building image ---"
docker build -t "$REGISTRY/$IMAGE:$TAG" -f "$CRON_DIR/Dockerfile" "$CRON_DIR/.."

# Step 2: Push to registry
echo -e "\n--- Pushing to registry ---"
docker push "$REGISTRY/$IMAGE:$TAG"

# Step 3: Create namespace if needed
echo -e "\n--- Creating namespace ---"
kubectl apply -f "$SCRIPT_DIR/namespace.yaml"

# Step 4: Apply secret (edit IMAP_PASS first!)
echo -e "\n--- Applying secret ---"
kubectl apply -f "$SCRIPT_DIR/secret.yaml"

# Step 5: Create ConfigMap from actual denylist/allowlist files
echo -e "\n--- Creating ConfigMap from deny/allow lists ---"
kubectl create configmap risa-triage-config \
  --from-file=denylist.md="$SCRIPT_DIR/denylist.md" \
  --from-file=allowlist.md="$SCRIPT_DIR/allowlist.md" \
  -n "$NAMESPACE" \
  --dry-run=client -o yaml | kubectl apply -f -

# Step 6: Apply CronJob
echo -e "\n--- Applying CronJob ---"
kubectl apply -f "$SCRIPT_DIR/cronjob.yaml"

echo -e "\n=== Deploy complete ==="
echo "Verify: kubectl get cronjobs -n $NAMESPACE"
echo "Trigger now: kubectl create job --from=cronjob/risa-triage risa-test -n $NAMESPACE"
echo "Check logs: kubectl logs -n $NAMESPACE job/risa-test"

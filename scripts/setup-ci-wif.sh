#!/usr/bin/env bash
# One-time setup: keyless GitHub Actions -> Google Cloud auth for GYB's live CI tests.
#
# Creates a Workload Identity Federation (WIF) pool + GitHub OIDC provider restricted to
# this repository, and lets it impersonate an existing service account that is ALREADY
# authorized for Domain-Wide Delegation in the test Workspace domain. No service account
# keys are created or stored anywhere.
#
# Usage:
#   PROJECT_ID=my-gyb-project \
#   SA_EMAIL=gyb-ci@my-gyb-project.iam.gserviceaccount.com \
#   ./scripts/setup-ci-wif.sh
#
# Requires: gcloud (authenticated with rights to manage IAM/WIF in PROJECT_ID) and gh.
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID to the GCP project that owns the DwD service account}"
: "${SA_EMAIL:?Set SA_EMAIL to the DwD-authorized service account email}"
REPO="${REPO:-GAM-team/got-your-back}"
POOL_ID="${POOL_ID:-gyb-github}"
PROVIDER_ID="${PROVIDER_ID:-github}"

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
POOL_NAME="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}"

echo "==> Enabling required APIs in ${PROJECT_ID}"
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  gmail.googleapis.com groupsmigration.googleapis.com --project "$PROJECT_ID"

echo "==> Creating workload identity pool ${POOL_ID} (ignored if it exists)"
gcloud iam workload-identity-pools create "$POOL_ID" \
  --project "$PROJECT_ID" --location global \
  --display-name "GYB GitHub Actions" 2>/dev/null || true

echo "==> Creating GitHub OIDC provider ${PROVIDER_ID} restricted to ${REPO}"
# Only trusted events from this exact repository can mint tokens. Fork pull requests never
# receive an id-token, and the CI job itself is limited to push/workflow_dispatch.
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --project "$PROJECT_ID" --location global \
  --workload-identity-pool "$POOL_ID" \
  --display-name "GitHub Actions OIDC" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.event_name=assertion.event_name,attribute.ref=assertion.ref" \
  --attribute-condition "assertion.repository == '${REPO}' && assertion.event_name in ['push', 'workflow_dispatch', 'schedule']" \
  2>/dev/null || echo "    (provider already exists; leaving it unchanged)"

echo "==> Allowing ${REPO} workflows to impersonate ${SA_EMAIL}"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/${POOL_NAME}/attribute.repository/${REPO}" \
  --condition=None >/dev/null

echo "==> Allowing ${SA_EMAIL} to sign its own Domain-Wide Delegation JWTs (IAM signJwt)"
# Keyless DwD has no local private key, so the delegation assertion is signed by IAM.
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --project "$PROJECT_ID" \
  --role roles/iam.serviceAccountTokenCreator \
  --member "serviceAccount:${SA_EMAIL}" \
  --condition=None >/dev/null

echo "==> Publishing non-secret repository variables for CI"
gh variable set GYB_WIF_PROVIDER --repo "$REPO" --body "${POOL_NAME}/providers/${PROVIDER_ID}"
gh variable set GYB_WIF_SERVICE_ACCOUNT --repo "$REPO" --body "$SA_EMAIL"

SA_CLIENT_ID="$(gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" --format='value(oauth2ClientId)')"
cat <<EOF

Done. The 'live-integration-wif' CI job will now run on the next push.

If ${SA_EMAIL} is NOT already authorized for Domain-Wide Delegation, a Workspace super
admin must add it at admin.google.com > Security > Access and data control > API controls >
Manage Domain Wide Delegation:
  Client ID: ${SA_CLIENT_ID}
  Scopes:    https://mail.google.com/,https://www.googleapis.com/auth/apps.groups.migration,https://www.googleapis.com/auth/userinfo.email
EOF

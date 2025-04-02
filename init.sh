#!/usr/bin/env bash

set -u

secrets=(
components/tunnels.map
components/cloudflare.env
components/cloudflared/cloudflared.env
components/coder/coder.env
components/dify/dify.env
components/n8n/n8n.env
components/rsshub/rsshub.env
components/tailscale/protonvpn.env
components/tailscale/tailscale.env
)

for secret in $secrets; do
    touch $secret
    curl -sSL $SECRET_MANAGER_API/$secret > $secret
done

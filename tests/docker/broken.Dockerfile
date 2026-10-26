# Development fixture: a Linux machine in a known vulnerable state, for the end-to-end check in CI.
# Every image is pinned by digest so the state cannot drift. Never publish or reuse this image.
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS node20
FROM oven/bun:1.3.9@sha256:856da45d07aeb62eb38ea3e7f9e1794c0143a4ff63efb00e6c4491b627e2a521 AS bun
FROM amazon/aws-cli:2.35.15@sha256:177c3f33d8b4b3d531a857b54289e8b101790ea9016c78431c417d8e681e7b2e AS awscli

# AL2023's ca-certificates still trusts emSign ECC Root CA - G3, so curl and the system Python accept it.
FROM amazonlinux:2023@sha256:c04a1012acc483977f61f7f91c28624a39a621e56a59781319a75dec528be9b6
RUN dnf install -y --setopt=install_weak_deps=False python3 python3-pip libstdc++ findutils \
      java-17-amazon-corretto-headless \
 && dnf clean all
COPY --from=node20 /usr/local/bin/node /usr/local/bin/node
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
# A venv with an old certifi, one whose botocore falls back to its own bundle, and an insecure .curlrc.
RUN ln -s /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws \
 && python3 -m venv /opt/old-certifi/.venv && /opt/old-certifi/.venv/bin/pip install -q 'certifi==2024.8.30' \
 && python3 -m venv /opt/botocore-only/.venv && /opt/botocore-only/.venv/bin/pip install -q 'botocore==1.42.26' \
 && printf 'insecure\n' > /root/.curlrc

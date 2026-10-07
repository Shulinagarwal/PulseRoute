FROM --platform=linux/amd64 docker.io/library/node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS toolchain

ARG TERRAFORM_VERSION=1.15.8
ARG OPENTOFU_VERSION=1.12.4
ARG AWS_PROVIDER_VERSION=6.50.0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_DEFAULT_REGION=us-east-1 \
    AWS_ENDPOINT_URL=http://aws:4566 \
    TF_PLUGIN_CACHE_DIR=/opt/terraform-plugin-cache \
    TF_CLI_CONFIG_FILE=/etc/terraformrc.offline

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl unzip git jq ripgrep python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g opencode-ai@1.17.8

RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir \
      awscli==1.45.51 boto3==1.43.51 jsonschema requests

ENV PATH=/opt/venv/bin:/usr/local/bin:${PATH}

RUN curl -fsSLo /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
 && curl -fsSLo /tmp/terraform_SHA256SUMS \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
 && cd /tmp \
 && grep "terraform_${TERRAFORM_VERSION}_linux_amd64.zip" terraform_SHA256SUMS \
      | sed 's/terraform_.*_linux_amd64.zip/terraform.zip/' | sha256sum -c - \
 && unzip -q /tmp/terraform.zip -d /usr/local/bin \
 && rm -f /tmp/terraform.zip /tmp/terraform_SHA256SUMS

RUN curl -fsSLo /tmp/tofu.zip \
      "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" \
 && curl -fsSLo /tmp/tofu_SHA256SUMS \
      "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_SHA256SUMS" \
 && cd /tmp \
 && grep "tofu_${OPENTOFU_VERSION}_linux_amd64.zip" tofu_SHA256SUMS \
      | sed 's/tofu_.*_linux_amd64.zip/tofu.zip/' | sha256sum -c - \
 && unzip -q /tmp/tofu.zip -d /usr/local/bin \
 && rm -f /tmp/tofu.zip /tmp/tofu_SHA256SUMS

RUN curl --retry 3 --max-time 300 -fsSLo /tmp/aws-provider.zip \
      "https://releases.hashicorp.com/terraform-provider-aws/${AWS_PROVIDER_VERSION}/terraform-provider-aws_${AWS_PROVIDER_VERSION}_linux_amd64.zip" \
 && curl --retry 3 --max-time 60 -fsSLo /tmp/aws-provider_SHA256SUMS \
      "https://releases.hashicorp.com/terraform-provider-aws/${AWS_PROVIDER_VERSION}/terraform-provider-aws_${AWS_PROVIDER_VERSION}_SHA256SUMS" \
 && cd /tmp \
 && grep "terraform-provider-aws_${AWS_PROVIDER_VERSION}_linux_amd64.zip" aws-provider_SHA256SUMS \
      | sed 's/terraform-provider-aws_.*_linux_amd64.zip/aws-provider.zip/' | sha256sum -c - \
 && mkdir -p "/opt/terraform-plugin-cache/registry.terraform.io/hashicorp/aws/${AWS_PROVIDER_VERSION}/linux_amd64" \
 && unzip -q /tmp/aws-provider.zip \
      -d "/opt/terraform-plugin-cache/registry.terraform.io/hashicorp/aws/${AWS_PROVIDER_VERSION}/linux_amd64" \
 && rm -f /tmp/aws-provider.zip /tmp/aws-provider_SHA256SUMS \
 && printf '%s\n' \
      'disable_checkpoint = true' \
      'provider_installation {' \
      '  filesystem_mirror {' \
      '    path    = "/opt/terraform-plugin-cache"' \
      '    include = ["registry.terraform.io/hashicorp/aws"]' \
      '  }' \
      '  direct {' \
      '    exclude = ["registry.terraform.io/hashicorp/aws"]' \
      '  }' \
      '}' > /etc/terraformrc.offline

# The read-only provider mirror and the writable runtime cache must differ.
ENV TF_PLUGIN_CACHE_DIR=/tmp/terraform-plugin-cache-runtime
RUN mkdir -p /tmp/terraform-plugin-cache-runtime \
 && chmod 1777 /tmp/terraform-plugin-cache-runtime

RUN groupadd --gid 10001 agent \
 && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash agent \
 && groupadd --gid 10002 verifier \
 && useradd --uid 10002 --gid 10002 --create-home --shell /bin/bash verifier \
 && chmod -R a+rX /opt/terraform-plugin-cache

# Login shells reset the Docker ENV PATH before loading /etc/profile.d.
RUN printf '%s\n' 'export PATH="/opt/venv/bin:$PATH"' > /etc/profile.d/pulseroute.sh

RUN su - agent -c 'python3 -c "import boto3, jsonschema, requests" && aws --version' \
 && su - verifier -c 'python3 -c "import boto3, jsonschema, requests" && aws --version'

FROM toolchain AS runner
COPY runtime/runner.py /opt/pulseroute-runner.py
# Submissions may read the public contracts at the paths the instruction names.
COPY contracts/ /workspace/contracts/
RUN mkdir -p /workspace/submission /workspace/config \
 && chmod -R a+rX /workspace/contracts \
 && chown -R agent:agent /workspace/submission /home/agent
WORKDIR /workspace
USER agent

FROM toolchain AS verifier
COPY . /tests/
COPY contracts/ /contracts/
RUN mkdir -p /workspace/submission /workspace/config /logs/verifier \
 && chmod 0755 /tests/test.sh \
 && chown -R verifier:verifier /logs/verifier /home/verifier
WORKDIR /workspace
USER verifier

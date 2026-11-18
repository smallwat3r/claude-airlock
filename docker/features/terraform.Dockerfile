# claude-feat: terraform
# claude-feat-md: Terraform with terraform-ls, without cloud credentials: init, validate, fmt and plan work against local or mocked state. Never run apply, destroy, import or state changes unless the user asks for that exact command
# claude-feat-lsp: {"terraform-ls": {"command": "terraform-ls", "args": ["serve"], "extensionToLanguage": {".tf": "terraform", ".tfvars": "terraform-vars"}}}

# Official zips from releases.hashicorp.com (apt would need HashiCorp's own
# repository), pinned and checksum-verified. The shas are recorded on purpose,
# fetching HashiCorp's SHA256SUMS from the same server would verify nothing.
# The base has no unzip, Python's zipfile extracts them instead. Terraform is
# under the BUSL since 1.6, terraform-ls under the MPL.
ARG TERRAFORM_VERSION=1.17.2
ARG TERRAFORM_SHA256_AMD64=e6f16b2f0b137ee5729caa8c4e79a3bae4ee261acd198a1fcfa8584a6296605b
ARG TERRAFORM_SHA256_ARM64=858e08c181a76b6b223e8c767a8e983922eebe2d062db949a2de66ce040c368c
ARG TERRAFORM_LS_VERSION=0.39.1
ARG TERRAFORM_LS_SHA256_AMD64=fe2a158e4a1a8ec8047dae9e06c439b468412aa579929ba28b2e1258cedef9c0
ARG TERRAFORM_LS_SHA256_ARM64=a72a6d9f72580cfc30cc06d3c973fd5f55790f62e3ddb195998435070d9af36d
RUN ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
    amd64) TF_SHA256="${TERRAFORM_SHA256_AMD64}"; TFLS_SHA256="${TERRAFORM_LS_SHA256_AMD64}" ;; \
    arm64) TF_SHA256="${TERRAFORM_SHA256_ARM64}"; TFLS_SHA256="${TERRAFORM_LS_SHA256_ARM64}" ;; \
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip" \
    -o /tmp/terraform.zip \
    && curl -fsSL "https://releases.hashicorp.com/terraform-ls/${TERRAFORM_LS_VERSION}/terraform-ls_${TERRAFORM_LS_VERSION}_linux_${ARCH}.zip" \
    -o /tmp/terraform-ls.zip \
    && printf '%s  %s\n' "${TF_SHA256}" /tmp/terraform.zip \
    "${TFLS_SHA256}" /tmp/terraform-ls.zip | sha256sum -c - \
    && python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract(sys.argv[2], sys.argv[3])' \
    /tmp/terraform.zip terraform /usr/local/bin \
    && python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract(sys.argv[2], sys.argv[3])' \
    /tmp/terraform-ls.zip terraform-ls /usr/local/bin \
    && chmod 755 /usr/local/bin/terraform /usr/local/bin/terraform-ls \
    && rm /tmp/terraform.zip /tmp/terraform-ls.zip

# Terraform phones checkpoint-api.hashicorp.com for update notices and keeps
# its signature in ~/.terraform.d, on the read-only home. Providers go to the
# project's own .terraform, which is writable, so no plugin cache is set.
ENV CHECKPOINT_DISABLE=1

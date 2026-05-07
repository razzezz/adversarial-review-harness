# .claude/tools/poc_image/Dockerfile
FROM python:3.12-slim

# Non-root user is already present in the base image (uid 65534 is nobody).
# We explicitly set PYTHONDONTWRITEBYTECODE to keep the rootfs clean-looking
# when --read-only is enforced at runtime.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install only the libraries PoCs might legitimately need to reproduce
# vulnerabilities in Python targets. Keep this list tight; a minimal
# image means a smaller attack surface inside the sandbox.
RUN pip install --no-cache-dir \
      pyyaml==6.0.2 \
      cryptography==44.0.0 \
      pycryptodome==3.21.0 \
      lxml==5.3.0 \
&& rm -rf /root/.cache
                                                                       
# The sandbox mounts /poc as read-only at runtime; nothing to do at build time.
WORKDIR /poc
USER 65534:65534

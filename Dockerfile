FROM ghcr.io/astral-sh/uv:python3.13-alpine

WORKDIR /app

# Copy pyproject.toml and lock file for dependency installation
COPY pyproject.toml uv.lock* ./

# Install dependencies and create the virtual environment
RUN uv sync --frozen --no-dev

# Copy application code
COPY contrastverify contrastverify
COPY version.py version.py
COPY verify.py verify.py
COPY verify-wrapper.py verify-wrapper.py

# Install the local package in the already created environment
RUN uv pip install --no-deps -e .

# Create backward compatibility symlink for GitLab users
RUN ln -s /app/verify-wrapper.py /verify.py && chmod +x /verify.py

# Use the virtual environment directly instead of uv run
ENTRYPOINT ["/app/.venv/bin/python3", "verify.py"]

# Stage 1: Builder
# Use Python 3.12-slim as the base image for building
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the files needed for installation to cache dependencies
COPY pyproject.toml README.md ./

# Create a virtual environment and install the package with browser dependencies
RUN python -m venv /opt/venv
# Enable venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies including the 'browser' extra for Playwright
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .[browser]

# Copy the rest of the application code
COPY chaos_kitten/ chaos_kitten/
COPY toys/ toys/
# Re-install package to include the source code
RUN pip install .[browser]


# Stage 2: Runtime
# Use Python 3.12-slim for the final image
FROM python:3.12-slim

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies required for Playwright
# Playwright needs some system libraries to run browsers
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2t64 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --from=builder /app/chaos_kitten /app/chaos_kitten
COPY --from=builder /app/toys /app/toys
# Need copying README and pyproject if the package metadata relies on them at runtime? 
# Usually installed in venv site-packages. But let's verify if CLI needs local files.
# The CLI typically imports from site-packages.

# Install Playwright browsers (chromium only to save space/time, unless configured otherwise)
# Since we installed playwright in the venv, we can use it.
# Note: chaos-kitten uses Playwright for XSS testing.
RUN playwright install chromium --with-deps

# Create directories for reports and toys if they need to be mounted
RUN mkdir -p /app/reports /app/toys

# Set entrypoint
ENTRYPOINT ["chaos-kitten"]

# Default command matches typical usage (help)
CMD ["--help"]

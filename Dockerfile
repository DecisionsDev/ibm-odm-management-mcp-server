FROM ghcr.io/astral-sh/uv:bookworm-slim AS builder
ARG PYTHON_VERSION=3.14
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_INSTALL_DIR=/python
ENV UV_PYTHON_PREFERENCE=only-managed

RUN uv python install ${PYTHON_VERSION}

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=README.md,target=README.md \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-dev --no-editable


FROM gcr.io/distroless/cc

LABEL name="IBM ODM Management MCP Server"
LABEL summary="MCP Server exposing the REST APIs of both IBM ODM Decision Center and the RES console"

COPY --from=builder --chown=nonroot:nonroot /python /python
COPY --from=builder --chown=nonroot:nonroot /app/.venv /app/.venv
USER nonroot
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["ibm-odm-management-mcp-server"]
CMD ["--transport", "streamable-http"]
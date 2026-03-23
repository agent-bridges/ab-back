FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen

COPY server.py ./

ENV UV_PROJECT_ENVIRONMENT=/opt/venv

EXPOSE 8420

CMD ["uv", "run", "python", "server.py"]

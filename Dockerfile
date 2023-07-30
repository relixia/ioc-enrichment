# Base image
FROM python:3.11

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH="${PATH}:/root/.local/bin"

# Set the working directory in the container
WORKDIR /app

# Copy only the pyproject.toml and poetry.lock files to leverage Poetry caching
COPY pyproject.toml poetry.lock /app/

# Install project dependencies with Poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-root

# Copy the entire 'src' directory into the container
COPY src/ /app/src/

# Set the environment variables for Celery
ENV C_FORCE_ROOT=1

# Set the working directory to /app/
WORKDIR /app/src/
# Use a slim Python image so the deployed API container stays small.
FROM python:3.11-slim

# /app is the working directory inside the container.
WORKDIR /app

# Install dependencies before copying source so Docker can cache this slower step.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy only the backend package into the container.
COPY backend /app/backend

# Expose the FastAPI port used by uvicorn.
EXPOSE 8000

# Start the API server when the container runs.
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

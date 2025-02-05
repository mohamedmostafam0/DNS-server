# Base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && apt-get clean \
    && update-ca-certificates

# Copy the requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY ./app /app

# Expose the DNS port
EXPOSE 1053

# Command to run the application
ENTRYPOINT ["python", "main.py"]

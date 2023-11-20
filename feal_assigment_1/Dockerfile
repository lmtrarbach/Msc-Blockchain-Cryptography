# Use an official Python runtime as a base image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

# Copy the Python code files into the container at /app
COPY vectorized2.py  execute_vectorized.py requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Build Cython code
RUN easycython vectorized2.py vectorized2.pyx

# Run execute_vectorized.py when the container launches
CMD ["python", "execute_vectorized.py"]

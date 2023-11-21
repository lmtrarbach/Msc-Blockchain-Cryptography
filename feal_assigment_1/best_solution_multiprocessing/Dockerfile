# Use an official Python runtime as a base image
FROM python:3.8

# Set the working directory 
WORKDIR /app

# Copy t files into  /app
COPY 8_multiprocessing.py execute.py requirements.txt /app/

# Install packages defined in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Build Cython code
RUN easycython 8_multiprocessing.py 8_multiprocessing.pyx

# Run execut.py
CMD ["python", "execute.py"]

FROM ubuntu:latest
# Update package lists and install gcc and make
RUN apt-get update && apt-get install -y gcc
RUN apt update && apt install -y curl \
RUN apt update && apt install -y iputils-ping netcat telnet
RUN apt update && apt install -y dnsutils


# Set the working directory inside the container
WORKDIR /workspace

# Copy the current directory contents into the container
COPY . /workspace

# Set the default command to run when the container starts
CMD ["./domainLookup", "google.com"]
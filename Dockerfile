###############################################################################
#
# Dockerfile for testing go-clam - DO NOT USE!!!
#
# Usage:
#   docker build -t go-clam .
#   docker run -it --rm go-clam
#
##################################################################################
# Use the official Go image as the base image
FROM golang:latest


# Set the Current Working Directory inside the container
WORKDIR /go/src/app

# Copy the source code into the container
COPY . .

# Install ClamAV and update virus definitions
RUN apt-get update && \
    apt-get install -y clamav && \
    freshclam

# Create the infected directory
RUN mkdir -p /root/infected

# Build the Go binary
RUN go build -o go-clam .

# set the entrypoint
#ENTRYPOINT ["./go-clam"]

# command to run the executable
CMD ["./go-clam", "-d", "/"]
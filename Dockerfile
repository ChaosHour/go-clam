# Use the official Go image as the base image
FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /go-clam

# Copy the source code into the container
COPY . .

# Install ClamAV and update virus definitions
RUN apt-get update && \
    apt-get install -y clamav && \
    freshclam

# Build the Go binary
RUN go build -o go-clam .

# set the entrypoint
ENTRYPOINT ["./go-clam"]
FROM golang:1.22.6-alpine AS build

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY ./go.mod ./go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY . ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /nfqueue-pol ./main.go 

RUN apk add nftables
RUN export PATH=$PATH:/usr/sbin

ENTRYPOINT [ "/nfqueue-pol" ]
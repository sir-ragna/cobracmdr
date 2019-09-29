
This is a very simple low-interaction ssh honeypot. It allows people to log in 
with any credentials and logs the commands that are attempted.

## Help

    $ ./main --help
    Usage of ./main:
    -a string
            address (default "0.0.0.0")
    -console
            Don't log to a file
    -l string
            output file (default "ssh-honeypot.log")
    -p string
            port (default "2222")

## Docker

Building and running with docker.

    docker build -t cobracmdr .
    docker run --rm -it -p 5022:2222 cobracmdr

The docker image is multi-stage. The resulting container should be less than 
20MB.

## Without Docker

    go get                  # Install deps
    go build -o main .      # Build
    ./main -p 5022 -console # Run and log to console

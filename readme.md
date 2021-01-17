
This is a very simple low-interaction ssh honeypot. It allows people to log in 
with any credentials and logs the commands that are attempted.

## Help

    $ ./main --help
    Usage of ./main:
      -a string
            address (default "0.0.0.0")
      -attempts int
            Logging attempts to stop before allowing sign in. (-1 never)
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

## Podman

Using podman and buildah is practically the same.

    buildah bud -t cobracmdr .
    podman run --rm -it -p 5022:2222 cobracmdr

When actually running this in production I advise to run detached and 
let the container run detached. Collect the logging with `podman logs`
instead of mounting a log file.

    podman run -d -p 22:2222 cobracmdr
    podman logs <container_id> > logs.txt

## Running natively

    go get                  # Install deps
    go build -o main .      # Build
    ./main -p 5022 -console # Run and log to console

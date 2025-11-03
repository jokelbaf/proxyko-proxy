# Proxyko Proxy

A simple forwarding proxy server written in Rust. A part of the [Proxyko](https://github.com/JokelBaf/proxyko) project.

## Development setup

1. Install Rust nightly from [rustup](https://rust-lang.org/tools/install/).
2. Clone this repository.
3. Copy `.env.example` to `.env` and fill in the required environment variables.
4. Run `cargo run` to build and start the proxy server.

## Production

Docker is the recommended way to run the Proxy in production. First, build the Docker image:

```sh
docker build -t proxyko-proxy:latest .
```

Then run the container:

```sh
docker run -d --name proxyko-proxy --restart unless-stopped -p 8041:8041 -e HOST=0.0.0.0 -e PORT=8041 -e INTERNAL_API_KEY=... -e PROXYKO_HOST=1.2.3.4 -e PROXYKO_PORT=8032 -e RUST_LOG=info proxyko-proxy:latest
```

> ![NOTE]
> You should use docker compose to run the container in production. See [this example](https://github.com/jokelbaf/proxyko/blob/master/docker-compose.yml) in Proxyko repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.

FROM python:3.12-bookworm
ENV DEBIAN_FRONTEND=noninteractive USER=root PYTHONPATH=/lab/src COVERLAB_CHROME=/usr/bin/chromium
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 tcpdump ethtool sudo nginx mosquitto mosquitto-clients curl openssl ca-certificates golang nodejs openjdk-17-jdk-headless chromium pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY upstream/stage_m /lab
WORKDIR /lab
RUN python -m pip install --no-cache-dir -r requirements.txt
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh && sh /tmp/rustup.sh -y --profile minimal --default-toolchain 1.88.0
RUN /root/.cargo/bin/cargo build --release --manifest-path clients/rust_client/Cargo.toml && cp clients/rust_client/target/release/coverlab-rust-client /usr/local/bin/coverlab-rust-client
RUN mkdir -p /opt/java && javac -d /opt/java clients/CoverlabJavaClient.java && go build -o /usr/local/bin/coverlab-go-client clients/go_client.go
ENV COVERLAB_RUST_CLIENT=/usr/local/bin/coverlab-rust-client COVERLAB_JAVA_CLIENT_DIR=/opt/java
COPY upstream/main /upstream-main
COPY source_lock.json upstream_files.json registry.json /provenance/
COPY entrypoint.py /entrypoint.py
COPY stage_controls.py /stage_controls.py
COPY browser_guard.py /browser_guard.py
COPY mechanic_patch.py /mechanic_patch.py
COPY browser_client.py /browser_client.py
ENTRYPOINT ["python", "/entrypoint.py"]
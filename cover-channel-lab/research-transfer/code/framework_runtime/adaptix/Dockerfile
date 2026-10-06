FROM cover-complete-wire:20261002
COPY tools/go1.25.4.linux-amd64.tar.gz /tmp/framework-go.tar.gz
RUN mkdir -p /opt/framework && tar -xzf /tmp/framework-go.tar.gz -C /opt/framework
ENV GOROOT=/opt/framework/go PATH=/opt/framework/go/bin:$PATH GOEXPERIMENT=jsonv2,greenteagc GOMAXPROCS=2 GOTOOLCHAIN=local
COPY sources/adaptix/AdaptixServer /src/AdaptixServer
COPY tools/gomodcache /opt/framework/gomodcache
ENV GOMODCACHE=/opt/framework/gomodcache GOPROXY=off
WORKDIR /src/AdaptixServer
RUN mkdir -p /framework/extenders && go build -buildvcs=false -ldflags="-s -w" -o /framework/adaptixserver
RUN cd extenders/gopher_listener_tcp && mkdir -p /framework/extenders/gopher_listener_tcp && go build -buildmode=plugin -ldflags="-s -w" -o /framework/extenders/gopher_listener_tcp/listener_gopher_tcp.so pl_main.go pl_transport.go map.go && cp config.yaml ax_config.axs /framework/extenders/gopher_listener_tcp/
RUN cd extenders/gopher_agent && mkdir -p /framework/extenders/gopher_agent && go build -buildmode=plugin -ldflags="-s -w" -o /framework/extenders/gopher_agent/agent_gopher.so pl_main.go pl_utils.go && cp config.yaml ax_config.axs /framework/extenders/gopher_agent/ && cp -r src_gopher /framework/extenders/gopher_agent/
WORKDIR /framework
COPY telemetry.go /framework/telemetry.go
RUN GOWORK=off go build -o /framework/telemetry /framework/telemetry.go
ENTRYPOINT ["python3"]

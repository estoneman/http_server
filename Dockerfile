FROM debian:stable-slim
RUN apt-get update && \
    apt-get install -y libasan8 git build-essential
RUN git clone 'https://estoneman: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@github.com/estoneman/http_server.git' && \
    cd http_server
RUN make -vB http_server
CMD ["ls"]

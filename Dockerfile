FROM golang:1.18.6 as compiler
ARG DIR_NAME
WORKDIR /app

COPY . .

RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.cn,direct && go mod tidy

RUN cd ${DIR_NAME} && go build -ldflags "-s -w" -o xdp .

FROM ubuntu:22.04
ARG DIR_NAME
WORKDIR /

COPY --from=compiler /app/${DIR_NAME}/xdp .
RUN chmod +x xdp

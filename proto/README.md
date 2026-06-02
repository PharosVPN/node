# proto — vendored wire contracts

This directory holds a **vendored copy** of the protobuf contracts node
implements. The canonical source is `docs/proto/` in the `PharosVPN/docs`
repository; `coxswain` owns these schemas (DESIGN §6, coxswain/BUILD.md).

`pharos/node/v1/control.proto` — the `NodeControl` service. coxswain is the gRPC
client; node is the server. Do **not** edit it here: change it in `docs/proto/`,
then re-vendor.

## Regenerating

Generated Go lands in `internal/gen/` and is committed. To regenerate after
re-vendoring the proto:

```
buf generate
```

`buf.gen.yaml` uses managed mode with the `protoc-gen-go` / `protoc-gen-go-grpc`
plugins. Install them with:

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

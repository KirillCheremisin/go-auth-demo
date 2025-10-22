@echo off
echo 🔧 Generating gRPC code...

protoc --proto_path="C:\protobuf\include" --proto_path=internal/grpc/proto --plugin=protoc-gen-go="C:\Files\vibe coding\go\bin\protoc-gen-go.exe" --plugin=protoc-gen-go-grpc="C:\Files\vibe coding\go\bin\protoc-gen-go-grpc.exe" --go_out=internal/grpc/proto --go_opt=paths=source_relative --go-grpc_out=internal/grpc/proto --go-grpc_opt=paths=source_relative internal/grpc/proto/user_service.proto

if %errorlevel% equ 0 (
    echo ✅ gRPC code generated successfully!
    dir internal\grpc\proto\*.pb.go
) else (
    echo ❌ Generation failed!
    pause
)
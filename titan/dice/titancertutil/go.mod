module github.com/google/platform-attestation/titan/dice/titancertutil

go 1.24.8

require (
	github.com/google/platform-attestation/titan/dice/scriberoots v0.0.0
	github.com/google/platform-attestation/titan/dice/titandice v0.0.0
)

require (
	github.com/google/go-tpm v0.9.6 // indirect
	golang.org/x/sys v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace github.com/google/platform-attestation/titan/dice/titandice => ../titandice

replace github.com/google/platform-attestation/titan/dice/scriberoots => ../scriberoots

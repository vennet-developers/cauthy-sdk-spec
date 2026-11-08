// Package cauthyapi holds the types of Cauthy's public API, generated from
// cauthy-sdk-spec's openapi/cauthy.yaml (types.gen.go), and the envelopes
// every answer comes in. Standard library only.
//
// A resource comes back as Data[T], a list as List[T], an error as ApiError:
//
//	var settings cauthyapi.Data[cauthyapi.WorkspaceAuthSettings]
//	err := json.NewDecoder(res.Body).Decode(&settings)
//
// An optional field is a pointer; a oneOf or anyOf field is json.RawMessage,
// for the caller to decode.
package cauthyapi

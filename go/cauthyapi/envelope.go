package cauthyapi

// Data is Cauthy's envelope for one resource: {"data": …}.
type Data[T any] struct {
	Data T `json:"data"`
}

// List is Cauthy's envelope for a collection: {"data": [...], "total_count": n}.
type List[T any] struct {
	Data       []T   `json:"data"`
	TotalCount int64 `json:"total_count"`
}

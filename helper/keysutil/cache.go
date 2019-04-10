package keysutil

type CacheType int

const (
	NoOp CacheType = iota
	SyncMap
	LRU
)

type Cache interface {
	CacheActive() bool
	Type() CacheType
	Delete(key interface{})
	Load(key interface{}) (value interface{}, ok bool)
	Store(key, value interface{})
	Size() int
}

package keysutil

type TransitNoOp struct{}

func NewTransitNoOp() *TransitNoOp {
	return &TransitNoOp{}
}

func (c *TransitNoOp) CacheActive() bool {
	return false
}

func (c *TransitNoOp) Type() CacheType {
	return NoOp
}

func (c *TransitNoOp) Delete(key interface{}) {
	return
}

func (c *TransitNoOp) Load(key interface{}) (value interface{}, ok bool) {
	return nil, false
}

func (c *TransitNoOp) Store(key, value interface{}) {
	return
}

func (c *TransitNoOp) Size() int {
	return 0
}

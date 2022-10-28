package engine

import (
	"sync"
)

var dedupValues int
var attributeValueDedupper map[AttributeValue]*AttributeValue
var dedupLock sync.RWMutex

func DedupValues(enable bool) {
	if enable {
		dedupValues++
	} else {
		dedupValues--
	}
	if dedupValues == 0 {
		attributeValueDedupper = nil
	} else if dedupValues > 0 && attributeValueDedupper == nil {
		attributeValueDedupper = make(map[AttributeValue]*AttributeValue)
	}
}

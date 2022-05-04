package engine

import "sync"

type FlexMutex struct {
	m       sync.RWMutex
	enabled uint64
}

func (fm *FlexMutex) Lock() {
	if fm.enabled != 0 {
		fm.m.Lock()
	}
}

func (fm *FlexMutex) Unlock() {
	if fm.enabled != 0 {
		fm.m.Unlock()
	}
}

func (fm *FlexMutex) RLock() {
	if fm.enabled != 0 {
		fm.m.RLock()
	}
}

func (fm *FlexMutex) RUnlock() {
	if fm.enabled != 0 {
		fm.m.RUnlock()
	}
}

func (fm *FlexMutex) Enable() {
	fm.enabled++
}

func (fm *FlexMutex) Disable() {
	if fm.enabled == 0 {
		panic("FlexMutex is already disabled")
	}
	fm.enabled--
}

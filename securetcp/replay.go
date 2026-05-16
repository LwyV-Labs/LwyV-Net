package securetcp

import "sync"

type ReplayWindow struct {
	mu     sync.Mutex
	window uint64
	maxSeq uint64
	bitmap uint64
	init   bool
}

func NewReplayWindow(window uint64) *ReplayWindow {
	if window == 0 || window > 64 {
		window = 64
	}
	return &ReplayWindow{window: window}
}

func (w *ReplayWindow) CheckAndMark(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.init {
		w.init = true
		w.maxSeq = seq
		w.bitmap = 1
		return true
	}

	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.maxSeq = seq
		return true
	}

	delta := w.maxSeq - seq
	if delta >= w.window || delta >= 64 {
		return false
	}
	mask := uint64(1) << delta
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

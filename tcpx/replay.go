package tcpx

type replayWindow struct {
	maxSeq uint64
	bits   uint64
	size   uint64
}

func newReplayWindow(size uint64) replayWindow {
	if size == 0 || size > 64 {
		size = 64
	}
	return replayWindow{size: size}
}

func (w *replayWindow) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if w.maxSeq == 0 {
		w.maxSeq = seq
		w.bits = 1
		return true
	}
	if seq > w.maxSeq {
		diff := seq - w.maxSeq
		if diff >= w.size {
			w.bits = 1
		} else {
			w.bits = (w.bits << diff) | 1
		}
		w.maxSeq = seq
		return true
	}
	diff := w.maxSeq - seq
	if diff >= w.size {
		return false
	}
	mask := uint64(1) << diff
	if w.bits&mask != 0 {
		return false
	}
	w.bits |= mask
	return true
}

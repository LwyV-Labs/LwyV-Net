package vlan

import "time"

const maxManagementEvents = 256

type ManagementEvent struct {
	ID      uint64    `json:"id"`
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	Payload any       `json:"payload,omitempty"`
}

func (s *Server) recordManagementEvent(eventType, message string, payload any) {
	s.managementMu.Lock()
	defer s.managementMu.Unlock()

	s.managementEventID++
	event := ManagementEvent{
		ID:      s.managementEventID,
		Time:    time.Now(),
		Type:    eventType,
		Message: message,
		Payload: payload,
	}
	s.managementEvents = append(s.managementEvents, event)
	if len(s.managementEvents) > maxManagementEvents {
		copy(s.managementEvents, s.managementEvents[len(s.managementEvents)-maxManagementEvents:])
		s.managementEvents = s.managementEvents[:maxManagementEvents]
	}
}

func (s *Server) managementEventsSnapshot() []ManagementEvent {
	s.managementMu.Lock()
	defer s.managementMu.Unlock()

	out := make([]ManagementEvent, len(s.managementEvents))
	copy(out, s.managementEvents)
	return out
}

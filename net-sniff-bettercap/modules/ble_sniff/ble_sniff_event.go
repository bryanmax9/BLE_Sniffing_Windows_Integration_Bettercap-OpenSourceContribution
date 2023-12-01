// Package ble_sniff declares the package name for the BLE sniffer module.
package ble_sniff

// Importing necessary packages:
// fmt for formatted I/O operations, time for time-related functionalities,
// and the bettercap session package for session management.
import (
	"fmt"
	"time"

	"github.com/bettercap/bettercap/session"
)

// SniffData defines a map with string keys and interface{} values to store arbitrary sniffing data.
type SniffData map[string]interface{}

// SnifferEvent struct represents a single sniffing event with various details about the captured packet.
type SnifferEvent struct {
	PacketTime  time.Time   `json:"time"`     // Time when the packet was captured.
	Protocol    string      `json:"protocol"` // Protocol used in the packet.
	Source      string      `json:"from"`     // Source address of the packet.
	Destination string      `json:"to"`       // Destination address of the packet.
	Message     string      `json:"message"`  // Formatted message string related to the packet.
	Data        interface{} `json:"data"`     // Arbitrary data associated with the packet.
}

// NewSnifferEvent constructs and returns a new SnifferEvent.
// Parameters include the time of the packet, protocol, source and destination addresses,
// arbitrary data, and a formatted message string.
func NewSnifferEvent(t time.Time, proto string, src string, dst string, data interface{}, format string, args ...interface{}) SnifferEvent {
	return SnifferEvent{
		PacketTime:  t,                                // Setting the packet time.
		Protocol:    proto,                            // Setting the protocol used.
		Source:      src,                              // Setting the source address.
		Destination: dst,                              // Setting the destination address.
		Message:     fmt.Sprintf(format, args...),     // Formatting and setting the message.
		Data:        data,                             // Associating arbitrary data with the event.
	}
}

// Push method of SnifferEvent pushes the event to the session's event manager.
func (e SnifferEvent) Push() {
	session.I.Events.Add("ble.sniff", e) // Adding the event to the session's event manager with a specific tag.
	session.I.Refresh()                  // Refreshing the session interface to reflect the new event.
}


// Package ble_sniff declares the package name for BLE sniffing functionalities.
package ble_sniff

// Importing necessary packages:
// time for handling time-related functionalities,
// and bettercap/log for logging purposes.
import (
	"time"

	"github.com/bettercap/bettercap/log"
)

// SnifferStats struct keeps track of various statistics for the sniffer.
type SnifferStats struct {
	NumAdvertisements uint64    // Count of total advertisements seen.
	NumMatched        uint64    // Count of packets matched with some criteria.
	NumDumped         uint64    // Count of packets dumped.
	NumWrote          uint64    // Count of packets written to a destination.
	Started           time.Time // Time when the sniffer was started.
	FirstPacket       time.Time // Time when the first packet was captured.
	LastPacket        time.Time // Time when the last packet was captured.
}

// NewSnifferStats initializes and returns a new instance of SnifferStats with default values.
func NewSnifferStats() *SnifferStats {
	return &SnifferStats{
		NumAdvertisements: 0,        // Initializing advertisement count as 0.
		NumMatched:        0,        // Initializing matched packet count as 0.
		NumDumped:         0,        // Initializing dumped packet count as 0.
		Started:           time.Now(), // Setting the start time to the current time.
		FirstPacket:       time.Time{}, // Initializing the first packet time as zero value.
		LastPacket:        time.Time{}, // Initializing the last packet time as zero value.
	}
}

// Print method for SnifferStats logs the statistics to the console.
func (s *SnifferStats) Print() error {
	first := "never" // Default value for the time of the first packet.
	last := "never"  // Default value for the time of the last packet.

	// Update the first packet time if it is not the zero value.
	if !s.FirstPacket.IsZero() {
		first = s.FirstPacket.String()
	}
	// Update the last packet time if it is not the zero value.
	if !s.LastPacket.IsZero() {
		last = s.LastPacket.String()
	}

	// Log various statistics.
	log.Info("Sniffer Started    : %s", s.Started) // Log the start time of the sniffer.
	log.Info("First Packet Seen  : %s", first)     // Log the time of the first packet seen.
	log.Info("Last Packet Seen   : %s", last)      // Log the time of the last packet seen.
	log.Info("Advertisements     : %d", s.NumAdvertisements) // Log the number of advertisements.
	log.Info("Matched Packets    : %d", s.NumMatched)        // Log the number of matched packets.
	log.Info("Dumped Packets     : %d", s.NumDumped)         // Log the number of dumped packets.

	return nil // Return nil error after printing.
}

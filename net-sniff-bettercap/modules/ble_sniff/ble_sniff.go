// Package ble_sniff declares the package name for BLE sniffing functionalities.
package ble_sniff

// Importing necessary packages:
// time for handling time-related functionalities,
// jstream for JSON streaming,
// and bettercap/session for session management in bettercap.
import (
	"time"

	"github.com/bcicen/jstream"
	"github.com/bettercap/bettercap/session"
)

// Sniffer struct extends session.SessionModule and contains sniffer-specific fields.
type Sniffer struct {
	session.SessionModule         // Embedding SessionModule for handling sessions.
	Stats         *SnifferStats   // Pointer to SnifferStats for tracking statistics.
	Ctx           *SnifferContext // Pointer to SnifferContext for context management.
	pktSourceChan chan *jstream.MetaValue // Channel for streaming parsed JSON data.
}

// NewSniffer creates and returns a new instance of Sniffer.
func NewSniffer(s *session.Session) *Sniffer {
	mod := &Sniffer{
		SessionModule: session.NewSessionModule("ble.sniff", s), // Initializing session module with name and session.
		Ctx:           nil, // Context initially set to nil.
		Stats:         nil, // Stats initially set to nil.
	}

	mod.Ctx = NewSnifferContext() // Setting up the sniffer context.

	// Adding various parameters to the module for configuration.
	mod.AddParam(session.NewBoolParameter("ble.sniff.verbose",
		"false",
		"If true, every captured and parsed packet will be sent to the events.stream for displaying, otherwise only the ones parsed at the application layer (sni, http, etc)."))
	mod.AddParam(session.NewStringParameter("ble.sniff.interface",
		"nRF Sniffer for Bluetooth LE",
		"",
		"extcap nRF Sniffer interface"))
	mod.AddParam(session.NewStringParameter("ble.sniff.source",
		"",
		"",
		"If set, the sniffer will read from this JSON file instead of the current interface."))
	mod.AddParam(session.NewStringParameter("ble.sniff.pcap",
		"",
		"",
		"If set, the sniffer will read from this PCAP file instead of the current interface."))
	mod.AddParam(session.NewStringParameter("ble.sniff.output",
		"",
		"",
		"If set, the sniffer will write to this json file."))
	mod.AddParam(session.NewStringParameter("ble.sniff.tshark",
		"tshark",
		"",
		"location of tshark command"))

	// Adding handlers to start and stop the sniffer module.
	mod.AddHandler(session.NewModuleHandler("ble.sniff on", "",
		"Start blework sniffer in background.",
		func(args []string) error {
			return mod.Start()
		}))
	mod.AddHandler(session.NewModuleHandler("ble.sniff off", "",
		"Stop blework sniffer in background.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod // Returning the initialized sniffer module.
}

// Name returns the name of the module.
func (mod Sniffer) Name() string {
	return "ble.sniff"
}

// Description returns a brief description of the module.
func (mod Sniffer) Description() string {
	return "Sniff packets from bluefruit sniffer"
}

// Author returns the author(s) of the module.
func (mod Sniffer) Author() string {
	return "<CSULB CECS 378 Group 6>"
}

// Configure method prepares the sniffer module for operation.
func (mod *Sniffer) Configure() error {
	var err error
	// Check if the module is already running.
	if mod.Running() {
		// Return an error if the module is already started.
		return session.ErrAlreadyStarted(mod.Name())
	} else if err, mod.Ctx = mod.GetContext(); err != nil {
		// If there is an error in getting the context, close the context and return the error.
		if mod.Ctx != nil {
			mod.Ctx.Close()
			mod.Ctx = nil
		}
		return err
	}
	return nil // Return nil if no error occurred.
}

// Start method starts the sniffer module.
func (mod *Sniffer) Start() error {
	// Configure the module before starting.
	if err := mod.Configure(); err != nil {
		return err
	}

	// Set the module as running and start the main logic in a go routine.
	return mod.SetRunning(true, func() {

		mod.Stats = NewSnifferStats() // Initialize sniffer statistics.

		// Set up the packet source channel to stream JSON data.
		mod.pktSourceChan = jstream.NewDecoder(mod.Ctx.Reader, 3).Stream()
		for packet := range mod.pktSourceChan {
			if !mod.Running() {
				// If the module is no longer running, exit the loop.
				mod.Debug("end pkt loop")
				break
			}

			now := time.Now() // Record the current time.
			if mod.Stats.FirstPacket.IsZero() {
				// If this is the first packet, record its time.
				mod.Stats.FirstPacket = now
			}
			mod.Stats.LastPacket = now // Update the last packet time.

			// Extract packet data as a map.
			packet_map, ok := packet.Value.(map[string]interface{})
			if !ok {
				// If the packet map is not valid, continue to the next packet.
				continue
			}

			// Extract BLE data from the packet.
			btle_data, ok := packet_map["btle"].(map[string]interface{})
			if !ok {
				// If BLE data is not present, continue to the next packet.
				continue
			}

			// Extract the access address from the BLE data.
			access_address, ok := btle_data["btle.access_address"].(string)
			if !ok {
				return
			}

			// Check if the access address matches a specific value.
			if access_address == "0x8e89bed6" {
				// Process the advertisement data.
				onAdvertisement(btle_data)
				// Increment the advertisement count.
				mod.Stats.NumAdvertisements++
			}

			// Increment the matched packets count.
			mod.Stats.NumMatched++
		}
		// Set the packet source channel to nil once the loop ends.
		mod.pktSourceChan = nil
	})
}

// Stop method stops the sniffer module.
func (mod *Sniffer) Stop() error {
	// Set the module as not running and handle the cleanup.
	return mod.SetRunning(false, func() {
		// Close the context as part of the cleanup.
		mod.Ctx.Close()
	})
}


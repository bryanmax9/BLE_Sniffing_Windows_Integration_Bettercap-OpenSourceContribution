// Package ble_sniff declares the package name for this BLE sniffing module.
package ble_sniff

// Importing necessary packages:
// bufio for buffered I/O operations, context for managing the lifecycle of processes,
// os for interacting with the operating system, os/exec for running external commands,
// regexp for regular expression functionality,
// and specific bettercap and islazy packages for BLE sniffing and UI enhancements.
import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"

	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/session"

	"github.com/evilsocket/islazy/tui"
)

// SnifferContext struct defines the context for the sniffer including various configuration parameters and state.
type SnifferContext struct {
	Reader        *bufio.Reader  // Reader to read the output from TShark or file.
	TSharkProc    *exec.Cmd      // Command representing the TShark process.
	TSharkRunning bool           // Flag to check if TShark is running.
	Interface     string         // Network interface to sniff on.
	Source        string         // Source file for offline analysis.
	PcapFile      string         // File path for pcap file.
	DumpLocal     bool           // Flag to include or exclude local packets.
	Verbose       bool           // Enable verbose logging.
	Filter        string         // BPF (Berkeley Packet Filter) string.
	Expression    string         // Regular expression for packet filtering.
	Compiled      *regexp.Regexp // Compiled regular expression.
	Output        string         // Output file or destination.
	OutputFile    *os.File       // File object for output.
}

// GetContext is a function associated with the Sniffer module to initialize and get the SnifferContext.
func (mod *Sniffer) GetContext() (error, *SnifferContext) {
	var err error

	// Creating a new sniffer context.
	ctx := NewSnifferContext()

	// Retrieving source parameter for the module, and handling errors.
	if err, ctx.Source = mod.StringParam("ble.sniff.source"); err != nil {
		return err, ctx
	}

	// Check if Source is not specified, then set up TShark for live sniffing.
	if ctx.Source == "" {

		// Retrieving TShark path and handling errors.
		err, tshark := mod.StringParam("ble.sniff.tshark")
		if err != nil {
			return err, ctx
		}

		// Retrieving network interface parameter and handling errors.
		if err, ctx.Interface = mod.StringParam("ble.sniff.interface"); err != nil {
			return err, ctx
		}

		// Retrieving pcap file parameter and handling errors.
		if err, ctx.PcapFile = mod.StringParam("ble.sniff.pcap"); err != nil {
			return err, ctx
		}

		// Setting up TShark command based on whether pcap file is provided or not.
		if ctx.PcapFile == "" {
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-i", ctx.Interface, "-T", "json")
		} else {
			ctx.TSharkProc = exec.CommandContext(context.Background(), tshark, "-T", "json", "-r", ctx.PcapFile)
		}

		// Creating a pipe to read stdout of TShark process and handling errors.
		tsharkout, err := ctx.TSharkProc.StdoutPipe()
		if err != nil {
			return err, ctx
		}

		// Starting the TShark process and handling errors.
		err = ctx.TSharkProc.Start()
		if err != nil {
			return err, ctx
		} else {
			ctx.TSharkRunning = true
		}

		// Setting up a buffered reader to read from TShark's stdout.
		ctx.Reader = bufio.NewReader(tsharkout)

	} else {
		// If Source is specified, open the file for reading and set up the buffered reader.
		file_reader, err := os.Open(ctx.Source)
		if err != nil {
			return err, ctx
		}

		ctx.Reader = bufio.NewReader(file_reader)
	}

	// Retrieving output file parameter and handling errors.
	if err, ctx.Output = mod.StringParam("ble.sniff.output"); err != nil {
		return err, ctx
	} else if ctx.Output != "" {
		// If output file is specified, create the file and handle errors.
		if ctx.OutputFile, err = os.Create(ctx.Output); err != nil {
			return err, ctx
		}
	}

	// Returning the context.
	return nil, ctx
}

// NewSnifferContext initializes and returns a new instance of SnifferContext with default values.
func NewSnifferContext() *SnifferContext {
	return &SnifferContext{
		Reader:        nil,         // Initializes Reader as nil; will be set later when TShark starts or a file is opened.
		TSharkProc:    nil,         // TShark process is initially nil, will be set up when required.
		TSharkRunning: false,       // Initial state of TShark is not running.
		Interface:     "",          // Network interface is initially empty, to be configured later.
		Source:        "",          // Source file for offline sniffing is initially empty.
		PcapFile:      "",          // Path for pcap file is initially empty.
		DumpLocal:     false,       // Flag for dumping local packets is initially set to false.
		Verbose:       false,       // Verbose logging is turned off initially.
		Filter:        "",          // BPF filter string is initially empty.
		Expression:    "",          // Regular expression for filtering is initially empty.
		Compiled:      nil,         // Compiled regular expression object is initially nil.
		Output:        "",          // Output destination is initially empty.
		OutputFile:    nil,         // Output file object is initially nil.
	}
}

// Declaring and initializing variables to represent 'yes' and 'no' with colors for UI display.
var (
	no  = tui.Red("no")    // 'no' string colored in red.
	yes = tui.Green("yes") // 'yes' string colored in green.
	// Map for converting boolean values to their colored string representations.
	yn  = map[bool]string{
		true:  yes, // True values are represented by 'yes' in green.
		false: no,  // False values are represented by 'no' in red.
	}
)

// Log method for SnifferContext logs various configuration parameters to the session log.
func (c *SnifferContext) Log(sess *session.Session) {
	// Logging the status of local packet dumping.
	log.Info("Skip local packets : %s", yn[c.DumpLocal])
	// Logging whether verbose logging is enabled.
	log.Info("Verbose            : %s", yn[c.Verbose])
	// Logging the BPF filter configuration.
	log.Info("BPF Filter         : '%s'", tui.Yellow(c.Filter))
	// Logging the regular expression used for filtering.
	log.Info("Regular expression : '%s'", tui.Yellow(c.Expression))
	// Logging the output file or destination.
	log.Info("File output        : '%s'", tui.Yellow(c.Output))
}

// Close method for SnifferContext handles the cleanup and resource release.
func (c *SnifferContext) Close() {
	// Checking if the TShark process is running.
	if c.TSharkRunning {
		// Attempting to kill the TShark process and handle potential errors.
		err := c.TSharkProc.Process.Kill()
		if err != nil {
			// Logging successful killing of the process.
			log.Debug("killed TSharkProc")
		} else {
			// Logging a warning if unable to kill the TShark process.
			log.Warning("could not kill TShark Process")
		}
	}

	// Checking if there is an output file that needs to be closed.
	if c.OutputFile != nil {
		// Logging the closure of the output file.
		log.Debug("closing output")
		c.OutputFile.Close() // Closing the output file.
		log.Debug("output closed")
		c.OutputFile = nil  // Setting the outputFile pointer to nil.
	}
}

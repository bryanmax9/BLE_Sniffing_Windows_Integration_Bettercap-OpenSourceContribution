// Package ble_sniff declares the package name for BLE sniffing functionalities.
package ble_sniff

// Importing necessary packages:
// strconv for string conversion, strings for string manipulation, time for time-related functions,
// and gatt for handling Bluetooth Low Energy attributes.
import (
	"strconv"
	"strings"
	"time"

	"github.com/bettercap/gatt"
)

// onProprietary is a function that processes proprietary BLE advertisement data.
func onProprietary(btleData map[string]interface{}) {

	// Extract the advertising address from the BLE data.
	advert_address, ok := btleData["btle.advertising_address"].(string)
	// If the address isn't present, return from the function.
	if !ok {
		return
	}

	// Extract advertising data from the BLE data.
	advertising_data, ok := btleData["btcommon.eir_ad.advertising_data"].(map[string]interface{})
	// If advertising data isn't present, return from the function.
	if !ok {
		return
	}

	// Extract EIR advertisement entry from the advertising data.
	eir_ad_entry, ok := advertising_data["btcommon.eir_ad.entry"].(map[string]interface{})
	// If the EIR advertisement entry isn't present, return from the function.
	if !ok {
		return
	}

	// Extract the data string from the EIR advertisement entry.
	data, ok := eir_ad_entry["btcommon.eir_ad.entry.data"].(string)
	// If the data isn't present, assign a default message to 'data'.
	if !ok {
		data = "No data could be retrieved"
	}

	// Extract the company code string from the EIR advertisement entry.
	company_code_string, ok := eir_ad_entry["btcommon.eir_ad.entry.company_id"].(string)
	// If the company code isn't present, return from the function.
	if !ok {
		return
	}

	// Remove the "0x" prefix from the company code string and convert it to an integer.
	company_code_hex := strings.Replace(company_code_string, "0x", "", -1)
	company_code, _ := strconv.ParseUint(company_code_hex, 16, 16)
	// Look up the company name using the company code in the gatt package.
	company_name := gatt.CompanyIdents[uint16(company_code)]

	// Create a new SnifferEvent with the current time, protocol "BLE ADVERT", source address,
	// destination as "BROADCAST", data, and a formatted message including the company name.
	// Then push this event.
	NewSnifferEvent(time.Now(),
		"BLE ADVERT",
		advert_address,
		"BROADCAST",
		data,
		"Proprietary %s Data",
		company_name,
	).Push()
}

// onAdvertisement is a function that processes generic BLE advertisements by calling onProprietary.
func onAdvertisement(btleData map[string]interface{}) {
	// It directly delegates the handling to onProprietary function.
	onProprietary(btleData)
}

//go:build !baremetal

package bluetooth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// Address contains a Bluetooth MAC address.
type Address struct {
	MACAddress
}

// Scan starts a BLE scan. It is stopped by a call to StopScan. A common pattern
// is to cancel the scan when a particular device has been found.
//
// On Linux with BlueZ, incoming packets cannot be observed directly. Instead,
// existing devices are watched for property changes. This closely simulates the
// behavior as if the actual packets were observed, but it has flaws: it is
// possible some events are missed and perhaps even possible that some events
// are duplicated.
func (a *Adapter) Scan(callback func(*Adapter, ScanResult), uuids []UUID) error {
	if a.scanCancelChan != nil {
		return errScanning
	}

	// Channel that will be closed when the scan is stopped.
	// Detecting whether the scan is stopped can be done by doing a non-blocking
	// read from it. If it succeeds, the scan is stopped.
	cancelChan := make(chan struct{})
	a.scanCancelChan = cancelChan

	// Convert UUIDs to strings.
	var uuidsStr []string
	for _, uuid := range uuids {
		uuidsStr = append(uuidsStr, uuid.String())
	}

	// This appears to be necessary to receive any BLE discovery results at all.
	defer a.adapter.Call("org.bluez.Adapter1.SetDiscoveryFilter", 0)
	err := a.adapter.Call("org.bluez.Adapter1.SetDiscoveryFilter", 0, map[string]interface{}{
		"Transport": "le",
		"UUIDs":     uuidsStr,
	}).Err
	if err != nil {
		return err
	}

	signal := make(chan *dbus.Signal)
	a.bus.Signal(signal)
	defer a.bus.RemoveSignal(signal)

	newObjectMatchOptions := []dbus.MatchOption{dbus.WithMatchInterface("org.freedesktop.DBus.ObjectManager")}
	a.bus.AddMatchSignal(newObjectMatchOptions...)
	defer a.bus.RemoveMatchSignal(newObjectMatchOptions...)

	// Check if the adapter is already discovering
	discovering, err := a.adapter.GetProperty("org.bluez.Adapter1.Discovering")
	if err != nil {
		return err
	}
	// if it is discovering, stop it
	if discovering.Value().(bool) {
		err = a.adapter.Call("org.bluez.Adapter1.StopDiscovery", 0).Err
		if err != nil {
			return err
		}
	}

	// Go through all connected devices and present the connected devices as
	// scan results. Also save the properties so that the full list of
	// properties is known on a PropertiesChanged signal. We can't present the
	// list of cached devices as scan results as devices may be cached for a
	// long time, long after they have moved out of range.

	var deviceList map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	err = a.bluez.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&deviceList)
	if err != nil {
		return err
	}

	devices := make(map[dbus.ObjectPath]map[string]dbus.Variant)
	for path, v := range deviceList {
		device, ok := v["org.bluez.Device1"]
		if !ok {
			continue // not a device
		}
		if !strings.HasPrefix(string(path), string(a.adapter.Path())) {
			continue // not part of our adapter
		}
		callback(a, makeScanResult(device))
		select {
		case <-cancelChan:
			return nil
		default:
		}
		devices[path] = device
	}

	// Instruct BlueZ to start discovering.
	err = a.adapter.Call("org.bluez.Adapter1.StartDiscovery", 0).Err
	if err != nil {
		return err
	}

	for {
		// Check whether the scan is stopped. This is necessary to avoid a race
		// condition between the signal channel and the cancelScan channel when
		// the callback calls StopScan() (no new callbacks may be called after
		// StopScan is called).
		select {
		case <-cancelChan:
			return a.adapter.Call("org.bluez.Adapter1.StopDiscovery", 0).Err
		default:
		}

		select {
		case sig := <-signal:
			// This channel receives anything that we watch for, so we'll have
			// to check for signals that are relevant to us.
			switch sig.Name {
			case "org.freedesktop.DBus.ObjectManager.InterfacesAdded":
				objectPath := sig.Body[0].(dbus.ObjectPath)
				interfaces := sig.Body[1].(map[string]map[string]dbus.Variant)
				rawprops, ok := interfaces["org.bluez.Device1"]
				if !ok {
					continue
				}
				devices[objectPath] = rawprops
				callback(a, makeScanResult(rawprops))
			case "org.freedesktop.DBus.ObjectManager.InterfacesRemoved":
				objectPath := sig.Body[0].(dbus.ObjectPath)
				delete(devices, objectPath)
			}
		case <-cancelChan:
			continue
		}
	}
	// unreachable
}

// StopScan stops any in-progress scan. It can be called from within a Scan
// callback to stop the current scan. If no scan is in progress, an error will
// be returned.
func (a *Adapter) StopScan() error {
	if a.scanCancelChan == nil {
		return errNotScanning
	}
	close(a.scanCancelChan)
	a.scanCancelChan = nil
	return nil
}

// isConnected returns whether the device is connected.
func (a *Adapter) isConnected(devicePath dbus.ObjectPath) (bool, error) {
	device := a.bus.Object("org.bluez", devicePath)
	connected, err := device.GetProperty("org.bluez.Device1.Connected")
	if err != nil {
		return false, err
	}
	return connected.Value().(bool), nil
}

// makeScanResult creates a ScanResult from a raw DBus device.
func makeScanResult(props map[string]dbus.Variant) ScanResult {
	// Assume the Address property is well-formed.
	addr, _ := ParseMAC(props["Address"].Value().(string))

	// Create a list of UUIDs.
	var serviceUUIDs []UUID
	for _, uuid := range props["UUIDs"].Value().([]string) {
		// Assume the UUID is well-formed.
		parsedUUID, _ := ParseUUID(uuid)
		serviceUUIDs = append(serviceUUIDs, parsedUUID)
	}

	a := Address{MACAddress{MAC: addr}}
	a.SetRandom(props["AddressType"].Value().(string) == "random")

	var manufacturerData []ManufacturerDataElement
	if mdata, ok := props["ManufacturerData"].Value().(map[uint16]dbus.Variant); ok {
		for k, v := range mdata {
			manufacturerData = append(manufacturerData, ManufacturerDataElement{
				CompanyID: k,
				Data:      v.Value().([]byte),
			})
		}
	}

	// Get optional properties.
	localName, _ := props["Name"].Value().(string)
	rssi, _ := props["RSSI"].Value().(int16)

	var serviceData []ServiceDataElement
	if sdata, ok := props["ServiceData"].Value().(map[string]dbus.Variant); ok {
		for k, v := range sdata {
			uuid, err := ParseUUID(k)
			if err != nil {
				continue
			}
			serviceData = append(serviceData, ServiceDataElement{
				UUID: uuid,
				Data: v.Value().([]byte),
			})
		}
	}

	return ScanResult{
		RSSI:    rssi,
		Address: a,
		AdvertisementPayload: &advertisementFields{
			AdvertisementFields{
				LocalName:        localName,
				ServiceUUIDs:     serviceUUIDs,
				ManufacturerData: manufacturerData,
				ServiceData:      serviceData,
			},
		},
	}
}

// Device is a connection to a remote peripheral.
type Device struct {
	Address   Address // the MAC address of the device
	Connected bool    // whether the device is currently connected

	devicePath dbus.ObjectPath // the DBus path of the device
	bus        *dbus.Conn      // the DBus connection
	device     dbus.BusObject  // bluez device interface
	bluez      dbus.BusObject  // bluez object
	adapter    *Adapter        // the adapter that was used to form this device connection
}

// Connect starts a connection attempt to the given peripheral device address.
func (a *Adapter) Connect(address Address, params ConnectionParams) (*Device, error) {
	devicePath := a.generateDevicePath(address)
	device := &Device{
		Address:    address,
		devicePath: devicePath,
		adapter:    a,
		Connected:  false,
	}

	// Connect to the device.
	err := device.connect()
	if err != nil {
		return nil, fmt.Errorf("bluetooth: failed to connect to device: %w", err)
	}

	return device, nil
}

// generateDevicePath generates a unique device path for the given address.
func (a *Adapter) generateDevicePath(address Address) dbus.ObjectPath {
	return dbus.ObjectPath(string(a.adapter.Path()) + "/dev_" + strings.Replace(address.MAC.String(), ":", "_", -1))
}

// watchForConnection watches for the connection status of the device and calls the appropriate connectHandler function
func (d *Device) watchForConnection() (connectChan chan struct{}, cancelChan chan struct{}) {
	signal := make(chan *dbus.Signal)
	d.adapter.bus.Signal(signal)
	connectChan = make(chan struct{})
	cancelChan = make(chan struct{})
	go d.watchForPropertyChanges(signal, connectChan, cancelChan)
	return connectChan, cancelChan
}

// connect attempts to connect to the device
func (d *Device) connect() error {
	if d.Connected {
		return nil
	}
	// if the bus is already connected, close it
	if d.bus != nil {
		err := d.bus.Close()
		if err != nil {
			return fmt.Errorf("bluetooth: failed to close existing d-bus connection: %w", err)
		}
	}
	// create a new d-bus connection
	bus, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("bluetooth: failed to connect to system bus: %w", err)
	}
	d.bus = bus
	connectChan, cancelChan := d.watchForConnection()
	// get the device object
	d.device = d.bus.Object("org.bluez", d.devicePath)
	d.bluez = d.bus.Object("org.bluez", dbus.ObjectPath("/"))
	// check if the device is already connected
	connected, err := d.adapter.isConnected(d.devicePath)
	if err != nil {
		close(cancelChan)
		return fmt.Errorf("bluetooth: failed to check if device is connected: %w", err)
	}
	if connected {
		d.Connected = true
	} else {

		err = d.device.Call("org.bluez.Device1.Connect", 0).Err
		if err != nil {
			close(cancelChan)
			d.bus.Close()
			return fmt.Errorf("bluetooth: failed to connect to device: %w", err)
		}
		<-connectChan
	}

	return nil
}

// watchForPropertyChanges listens for property change signals on the given channel and handles them accordingly.
// It checks for changes in the "Connected" property of the "org.bluez.Device1" interface and calls the appropriate
// connectHandler function from the adapter. If the "Connected" property is true, it closes the connectChan channel.
// The function continues to listen for signals until the signal channel is closed.
//
// Parameters:
//   - signal: A channel of dbus signals to listen for property change signals.
//   - connectChan: A channel used to notify when the device is connected.
func (d *Device) watchForPropertyChanges(signal chan *dbus.Signal, connectChan chan struct{}, cancelChan chan struct{}) {
	propertiesChangedMatchOptions := []dbus.MatchOption{
		dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
		dbus.WithMatchObjectPath(d.device.Path()),
	}
	d.adapter.bus.AddMatchSignal(propertiesChangedMatchOptions...)
	defer d.adapter.bus.RemoveMatchSignal(propertiesChangedMatchOptions...)
	defer d.adapter.bus.RemoveSignal(signal)

	for {
		select {
		case <-cancelChan:
			return
		case sig := <-signal:
			if sig.Name != "org.freedesktop.DBus.Properties.PropertiesChanged" {
				continue
			}
			interfaceName, changes := parseSignal(sig)
			if interfaceName != "org.bluez.Device1" {
				continue
			}
			if sig.Path != d.device.Path() {
				continue
			}
			if connected, ok := changes["Connected"].Value().(bool); ok {
				if connected == d.Connected {
					continue
				}
				go d.adapter.connectHandler(d, connected)
				d.Connected = connected
				if connected {
					close(connectChan)
				} else {
					// close d-bus connection
					d.bus.Close()
					return
				}

			}
		}
	}
}

// parseSignal parses a signal from the DBus and extracts interface name and changes map.
func parseSignal(sig *dbus.Signal) (interfaceName string, changes map[string]dbus.Variant) {
	interfaceName = sig.Body[0].(string)
	changes = sig.Body[1].(map[string]dbus.Variant)
	return
}

// Disconnect from the BLE device. This method is non-blocking and does not
// wait until the connection is fully gone.
func (d Device) Disconnect() error {
	// we don't call our cancel function here, instead we wait for the
	// property change in `watchForConnect` and cancel things then
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return d.device.CallWithContext(ctx, "org.bluez.Device1.Disconnect", 0).Err
}

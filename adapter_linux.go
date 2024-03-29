//go:build !baremetal

// Some documentation for the BlueZ D-Bus interface:
// https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc

package bluetooth

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const defaultAdapter = "hci0"

type Adapter struct {
	id                   string
	scanCancelChan       chan struct{}
	bus                  *dbus.Conn
	bluez                dbus.BusObject // object at /
	adapter              dbus.BusObject // object at /org/bluez/hciX
	address              string
	defaultAdvertisement *Advertisement

	connectHandler func(device Device, connected bool)
}

// DefaultAdapter is the default adapter on the system. On Linux, it is the
// first adapter available.
//
// Make sure to call Enable() before using it to initialize the adapter.
var DefaultAdapter = &Adapter{
	id: defaultAdapter,
	connectHandler: func(device Device, connected bool) {
	},
}

// Enable configures the BLE stack. It must be called before any
// Bluetooth-related calls (unless otherwise indicated).
func (a *Adapter) Enable() (err error) {
	bus, err := dbus.SystemBus()
	if err != nil {
		return err
	}
	a.bus = bus
	a.bluez = a.bus.Object("org.bluez", dbus.ObjectPath("/"))
	a.adapter = a.bus.Object("org.bluez", dbus.ObjectPath("/org/bluez/"+a.id))

	// get a list of connected devices
	obj := a.bus.Object("org.bluez", "/")
    var objects map[dbus.ObjectPath]map[string]map[string]dbus.Variant
    err = obj.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&objects)
    if err != nil {
        return err
    }
	// remove all devices
	for path := range objects {
		// fmt.Println(objects[path])
		// if the device is a peripheral, remove it
		if objects[path]["org.bluez.Device1"]!= nil {
			// remove device
			obj := a.bus.Object("org.bluez", "/org/bluez/hci0")
			err = obj.Call("org.bluez.Adapter1.RemoveDevice", 0, path).Store()
			if err != nil {
				return err
			}
		}
	}

	// get the adapter address
	addr, err := a.adapter.GetProperty("org.bluez.Adapter1.Address")
	if err != nil {
		if err, ok := err.(dbus.Error); ok && err.Name == "org.freedesktop.DBus.Error.UnknownObject" {
			return fmt.Errorf("bluetooth: adapter %s does not exist", a.adapter.Path())
		}
		return fmt.Errorf("could not activate BlueZ adapter: %w", err)
	}
	addr.Store(&a.address)
	
	// Add a match for properties changed signals
	// propertiesChangedMatchOptions := []dbus.MatchOption{dbus.WithMatchInterface("org.freedesktop.DBus.Properties")}
	// a.bus.AddMatchSignal(propertiesChangedMatchOptions...)

	return nil
}

func (a *Adapter) Address() (MACAddress, error) {
	if a.address == "" {
		return MACAddress{}, errors.New("adapter not enabled")
	}
	mac, err := ParseMAC(a.address)
	if err != nil {
		return MACAddress{}, err
	}
	return MACAddress{MAC: mac}, nil
}

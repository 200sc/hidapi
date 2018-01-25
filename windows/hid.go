package hid

import (
	"math"
	"syscall"

	"github.com/oakmound/w32"
)

/*******************************************************
 HIDAPI - Multi-Platform library for
 communication with HID devices.

 Alan Ott
 Signal 11 Software

 8/22/2009

 Copyright 2009, All Rights Reserved.

 At the discretion of the user of this library,
 this software may be licensed under the terms of the
 GNU General Public License v3, a BSD-Style license, or the
 original HIDAPI license as outlined in the LICENSE.txt,
 LICENSE-gpl3.txt, LICENSE-bsd.txt, and LICENSE-orig.txt
 files located at the root of the source distribution.
 These files may also be found in the public source
 code repository located at:
        http://github.com/signal11/hidapi .
********************************************************/

/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
const MAX_STRING_WCHARS = 0xFF

const (
	S11VendorID  = 0xa0a0
	S11ProductID = 0x0001

	P32VendorID  = 0x04d8
	P32ProductID = 0x3f

	PICPGMVendorID  = 0x04d8
	PICPGMProductID = 0x0033
)

const HIDP_STATUS_SUCCESS = 0x110000

/* Since we're not building with the DDK, and the HID header
files aren't part of the SDK, we have to define all this
stuff here. In lookup_functions(), the function pointers
defined below are set. */
type HIDD_ATTRIBUTES struct {
	Size          uint32
	VendorID      uint16
	ProductID     uint16
	VersionNumber uint16
}

type USAGE uint16
type HIDP_CAPS struct {
	Usage                     USAGE
	UsagePage                 USAGE
	InputReportByteLength     uint16
	OutputReportByteLength    uint16
	FeatureReportByteLength   uint16
	Reserved                  [17]uint16
	fields_not_used_by_hidapi [10]uint16
}
type PHIDP_PREPARSED_DATA interface{}

var lib_handle HMODULE
var initialized bool

type hid_device struct {
	device_handle        w32.HANDLE
	blocking             bool
	output_report_length uint16
	input_report_length  int
	last_error_str       string
	last_error_num       uint32
	read_pending         bool
	read_buf             string
	ol                   OVERLAPPED
}

type hid_device_info struct {
	/** Platform-specific device path */
	path string
	/** Device Vendor ID */
	vendor_id uint16
	/** Device Product ID */
	product_id uint16
	/** Serial Number */
	serial_number string
	/** Device Release Number in binary-coded decimal,
	also known as Device Version Number */
	release_number uint16
	/** Manufacturer String */
	manufacturer_string string
	/** Product string */
	product_string string
	/** Usage Page for this Device/Interface
	(Windows/Mac only). */
	usage_page uint16
	/** Usage for this Device/Interface
	(Windows/Mac only).*/
	usage uint16
	/** The USB interface which this logical device
	represents. Valid on both Linux implementations
	in all cases, and valid on the Windows implementation
	only if the device contains more than one interface. */
	interface_number int
}

type OVERLAPPED struct {
	Internal     *uint32
	InternalHigh *uint32
	Offset       uint32
	OffsetHigh   uint32
	HEvent       w32.HANDLE
}

const InvalidHandle w32.HANDLE = math.MaxInt32

func new_hid_device() *hid_device {
	dev := &hid_device{}
	dev.device_handle = InvalidHandle
	dev.blocking = true
	dev.output_report_length = 0
	dev.input_report_length = 0
	dev.last_error_str = ""
	dev.last_error_num = 0
	dev.read_pending = false
	dev.read_buf = ""
	dev.ol.HEvent = w32.CreateEvent(nil, false, false /*initial state f=nonsignaled*/, "")

	return dev
}

func free_hid_device(dev *hid_device) {
	syscall.Close(syscall.Handle(dev.ol.HEvent))
	syscall.Close(syscall.Handle(dev.device_handle))
}

func register_error(device *hid_device, op string) {
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|
		FORMAT_MESSAGE_FROM_SYSTEM|
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nil,
		w32.GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPVOID)&msg, 0, /*sz*/
		nil)

	/* Store the message off in the Device entry so that
	   the hid_error() function can pick it up. */
	device.last_error_str = msg
}

func open_device(path string, enumerate bool) w32.HANDLE {
	var desired_access uint32
	if !enumerate {
		desired_access = (GENERIC_WRITE | GENERIC_READ)
	}

	share_mode := FILE_SHARE_READ | FILE_SHARE_WRITE

	handle := CreateFileA(path,
		desired_access,
		share_mode,
		nil,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED, /*FILE_ATTRIBUTE_NORMAL,*/
		0)

	return handle
}

func hid_init() int {
	if !initialized {
		if lookup_functions() < 0 {
			hid_exit()
			return -1
		}
		initialized = true
	}
	return 0
}

func hid_exit() int {
	if lib_handle != nil {
		lib_handle.Release()
	}
	lib_handle = nil
	initialized = false
	return 0
}

func hid_enumerate(vendor_id, product_id uint16) []hid_device_info {
	var res bool
	var root []hid_device_info /* return object */
	var cur_dev *hid_device_info

	/* Windows objects for interacting with the driver. */

	InterfaceClassGuid := GUID{0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}}
	var devinfo_data SP_DEVINFO_DATA
	var device_interface_data SP_DEVICE_INTERFACE_DATA
	var device_interface_detail_data *SP_DEVICE_INTERFACE_DETAIL_DATA_A
	var device_info_set HDEVINFO = InvalidHandle
	device_index := 0
	i := 0

	if hid_init() < 0 {
		return nil
	}

	/* Initialize the Windows objects. */
	memset(&devinfo_data, 0x0, sizeof(devinfo_data))
	devinfo_data.cbSize = sizeof(SP_DEVINFO_DATA)
	device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA)

	/* Get information for all the devices belonging to the HID class. */
	device_info_set = SetupDiGetClassDevsA(&InterfaceClassGuid, nil, nil, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE)

	/* Iterate over each device in the HID class, looking for the right one. */

	for {
		var write_handle w32.HANDLE = InvalidHandle
		required_size := 0
		var attrib HIDD_ATTRIBUTES

		res = SetupDiEnumDeviceInterfaces(device_info_set,
			nil,
			&InterfaceClassGuid,
			device_index,
			&device_interface_data)

		if !res {
			/* A return of false from this function means that
			   there are no more devices. */
			break
		}

		/* Call with 0-sized detail size, and let the function
		   tell us how long the detail struct needs to be. The
		   size is put in &required_size. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
			&device_interface_data,
			nil,
			0,
			&required_size,
			nil)

		/* Allocate a long enough structure for device_interface_detail_data. */
		device_interface_detail_data = &SP_DEVICE_INTERFACE_DETAIL_DATA_A{}
		device_interface_detail_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A)

		/* Get the detailed data for this device. The detail data gives us
		   the device path for this device, which is then passed into
		   CreateFile() to get a handle to the device. */
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
			&device_interface_data,
			device_interface_detail_data,
			required_size,
			nil,
			nil)

		if !res {
			/* register_error(dev, "Unable to call SetupDiGetDeviceInterfaceDetail")
			   Continue to the next device. */
			goto cont
		}

		/* Make sure this device is of Setup Class "HIDClass" and has a
		   driver bound to it. */
		i == 0
		for {
			var driver_name string

			/* Populate devinfo_data. This function will return failure
			   when there are no more interfaces left. */
			res = SetupDiEnumDeviceInfo(device_info_set, i, &devinfo_data)
			if !res {
				goto cont
			}

			res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data,
				SPDRP_CLASS, nil, driver_name, 256, nil)
			if !res {
				goto cont
			}

			if strcmp(driver_name, "HIDClass") == 0 {
				/* See if there's a driver bound. */
				res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data,
					SPDRP_DRIVER, nil, driver_name, 256, nil)
				if res {
					break
				}
			}
			i++
		}

		//wprintf(L"HandleName: %s\n", device_interface_detail_data.DevicePath)

		/* Open a handle to the device */
		write_handle = open_device(device_interface_detail_data.DevicePath, true)

		/* Check validity of write_handle. */
		if write_handle == InvalidHandle {
			/* Unable to open the device. */
			//register_error(dev, "CreateFile")
			goto cont_close
		}

		/* Get the Vendor ID and Product ID for this device. */
		attrib.Size = sizeof(HIDD_ATTRIBUTES)
		HidD_GetAttributes(write_handle, &attrib)
		//wprintf(L"Product/Vendor: %x %x\n", attrib.ProductID, attrib.VendorID)

		/* Check the VID/PID to see if we should add this
		   device to the enumeration list. */
		if (vendor_id == 0x0 || attrib.VendorID == vendor_id) &&
			(product_id == 0x0 || attrib.ProductID == product_id) {

			str := ""
			var tmp *hid_device_info
			var pp_data *HIDP_PREPARSED_DATA
			var caps HIDP_CAPS

			var nt_res NTSTATUS
			var wstr [512]rune /* TODO: Determine Size */
			var ln int

			/* VID/PID match. Create the record. */
			tmp = &hid_device_info{}
			if cur_dev != nil {
				cur_dev.next = tmp
			} else {
				root = append(root, tmp)
			}
			cur_dev = tmp

			/* Get the Usage Page and Usage for this device. */
			res = HidD_GetPreparsedData(write_handle, &pp_data)
			if res {
				nt_res = HidP_GetCaps(pp_data, &caps)
				if nt_res == HIDP_STATUS_SUCCESS {
					cur_dev.usage_page = caps.UsagePage
					cur_dev.usage = caps.Usage
				}

				HidD_FreePreparsedData(pp_data)
			}

			/* Fill out the record */
			cur_dev.next = nil
			str = device_interface_detail_data.DevicePath
			if str {
				cur_dev.path = str[:] + '\000'
			} else {
				cur_dev.path = ""
			}

			/* Serial Number */
			res = HidD_GetSerialNumberString(write_handle, wstr, sizeof(wstr))
			wstr[512-1] = 0x0000
			if res {
				cur_dev.serial_number = _wcsdup(wstr)
			}

			/* Manufacturer String */
			res = HidD_GetManufacturerString(write_handle, wstr, sizeof(wstr))
			wstr[512-1] = 0x0000
			if res {
				cur_dev.manufacturer_string = _wcsdup(wstr)
			}

			/* Product String */
			res = HidD_GetProductString(write_handle, wstr, sizeof(wstr))
			wstr[512-1] = 0x0000
			if res {
				cur_dev.product_string = _wcsdup(wstr)
			}

			/* VID/PID */
			cur_dev.vendor_id = attrib.VendorID
			cur_dev.product_id = attrib.ProductID

			/* Release Number */
			cur_dev.release_number = attrib.VersionNumber

			/* Interface Number. It can sometimes be parsed out of the path
			   on Windows if a device has multiple interfaces. See
			   http://msdn.microsoft.com/en-us/windows/hardware/gg487473 or
			   search for "Hardware IDs for HID Devices" at MSDN. If it's not
			   in the path, it's set to -1. */
			cur_dev.interface_number = -1
			if cur_dev.path {
				char * interface_component = strstr(cur_dev.path, "&mi_")
				if interface_component {
					char * hex_str = interface_component + 4
					char * endptr = nil
					cur_dev.interface_number = strtol(hex_str, &endptr, 16)
					if endptr == hex_str {
						/* The parsing failed. Set interface_number to -1. */
						cur_dev.interface_number = -1
					}
				}
			}
		}

	cont_close:
		CloseHandle(write_handle)
	cont:
		/* We no longer need the detail data. It can be freed */
		free(device_interface_detail_data)

		device_index++

	}

	/* Close the device information handle. */
	SetupDiDestroyDeviceInfoList(device_info_set)

	return root

}

func hid_open(vendor_id, product_id uint16, serial_number string) *hid_device {
	/* TODO: Merge this functions with the Linux version. This function should be platform independent. */
	var path_to_open string

	devs := hid_enumerate(vendor_id, product_id)
	for _, cur_dev := range devs {
		if cur_dev.vendor_id == vendor_id &&
			cur_dev.product_id == product_id {
			if serial_number {
				if wcscmp(serial_number, cur_dev.serial_number) == 0 {
					path_to_open = cur_dev.path
					break
				}
			} else {
				path_to_open = cur_dev.path
				break
			}
		}
		cur_dev = cur_dev.next
	}

	if path_to_open {
		/* Open the device */
		return hid_open_path(path_to_open)
	}

	return nil
}

func hid_open_path(path string) *hid_device {
	var dev *hid_device
	var caps HIDP_CAPS
	var pp_data PHIDP_PREPARSED_DATA
	var res bool
	var nt_res NTSTATUS

	if hid_init() < 0 {
		return nil
	}

	dev = new_hid_device()

	/* Open a handle to the device */
	dev.device_handle = open_device(path, false)

	/* Check validity of write_handle. */
	if dev.device_handle == InvalidHandle {
		/* Unable to open the device. */
		register_error(dev, "CreateFile")
		goto err
	}

	/* Set the Input Report buffer size to 64 reports. */
	res = HidD_SetNumInputBuffers(dev.device_handle, 64)
	if !res {
		register_error(dev, "HidD_SetNumInputBuffers")
		goto err
	}

	/* Get the Input Report length for the device. */
	res = HidD_GetPreparsedData(dev.device_handle, &pp_data)
	if !res {
		register_error(dev, "HidD_GetPreparsedData")
		goto err
	}
	nt_res = HidP_GetCaps(pp_data, &caps)
	if nt_res != HIDP_STATUS_SUCCESS {
		register_error(dev, "HidP_GetCaps")
		goto err_pp_data
	}
	dev.output_report_length = caps.OutputReportByteLength
	dev.input_report_length = caps.InputReportByteLength
	HidD_FreePreparsedData(pp_data)

	dev.read_buf = make(string, dev.input_report_length)

	return dev

err_pp_data:
	HidD_FreePreparsedData(pp_data)
err:
	free_hid_device(dev)
	return nil
}

func hid_write(dev *hid_device, data string, length int) int {
	var bytes_written uint32
	var res bool

	var ol OVERLAPPED
	var buf string

	/* Make sure the right number of bytes are passed to WriteFile. Windows
	   expects the number of bytes which are in the _longest_ report (plus
	   one for the report number) bytes even if the data is a report
	   which is shorter than that. Windows gives us this value in
	   caps.OutputReportByteLength. If a user passes in fewer bytes than this,
	   create a temporary buffer which is the proper size. */
	if length >= dev.output_report_length {
		/* The user passed the right number of bytes. Use the buffer as-is. */
		buf = data
	} else {
		/* Create a temporary buffer and copy the user's data
		   into it, padding the rest with zeros. */
		buf = data
		// string builder?
		for i := 0; i < dev.output_report_length-length; i++ {
			buf += "0"
		}
		length = dev.output_report_length
	}

	res = WriteFile(dev.device_handle, buf, length, nil, &ol)

	if !res {
		if GetLastError() != ERROR_IO_PENDING {
			/* WriteFile() failed. Return error. */
			register_error(dev, "WriteFile")
			return -1
		}
	}

	/* Wait here until the write is done. This makes
	   hid_write() synchronous. */
	res = GetOverlappedResult(dev.device_handle, &ol, &bytes_written, true /*wait*/)
	if !res {
		/* The Write operation failed. */
		register_error(dev, "WriteFile")
		return -1
	}

	return bytes_written
}

func hid_read_timeout(dev *hid_device, data string, length, milliseconds int) int {
	var uint32 bytes_read
	copy_len := 0
	var res bool

	/* Copy the handle for convenience. */
	ev := dev.ol.hEvent

	if !dev.read_pending {
		/* Start an Overlapped I/O read. */
		dev.read_pending = true
		memset(dev.read_buf, 0, dev.input_report_length)
		ResetEvent(ev)
		res = ReadFile(dev.device_handle, dev.read_buf, dev.input_report_length, &bytes_read, &dev.ol)

		if !res {
			if GetLastError() != ERROR_IO_PENDING {
				/* ReadFile() has failed.
				   Clean up and return error. */
				CancelIo(dev.device_handle)
				dev.read_pending = false
				register_error(dev, "GetOverlappedResult")
				return -1
			}
		}
	}

	if milliseconds >= 0 {
		/* See if there is any data yet. */
		res = WaitForSingleObject(ev, milliseconds)
		if res != WAIT_OBJECT_0 {
			/* There was no data this time. Return zero bytes available,
			   but leave the Overlapped I/O running. */
			return 0
		}
	}

	/* Either WaitForSingleObject() told us that ReadFile has completed, or
	   we are in non-blocking mode. Get the number of bytes read. The actual
	   data has been copied to the data[] array which was passed to ReadFile(). */
	res = GetOverlappedResult(dev.device_handle, &dev.ol, &bytes_read, true /*wait*/)

	/* Set pending back to false, even if GetOverlappedResult() returned error. */
	dev.read_pending = false

	if res && bytes_read > 0 {
		if dev.read_buf[0] == 0x0 {
			/* If report numbers aren't being used, but Windows sticks a report
			   number (0x0) on the beginning of the report anyway. To make this
			   work like the other platforms, and to make it work more like the
			   HID spec, we'll skip over this byte. */
			bytes_read--
			copy_len = length
			if length > bytes_read {
				copy_len = bytes_read
			}
			copy(dev.read_buf[1:], data)
		} else {
			/* Copy the whole buffer, report number and all. */
			copy_len = length
			if length > bytes_read {
				copy_len = bytes_read
			}
			copy(dev.read_buf[1:], data)

		}
	}

	if !res {
		register_error(dev, "GetOverlappedResult")
		return -1
	}

	return copy_len
}

func hid_read(dev *hid_device, data string, length int) int {
	ms := -1
	if !dev.blocking {
		ms = 0
	}
	return hid_read_timeout(dev, data, length, ms)
}

func hid_set_nonblocking(dev *hid_device, nonblock int) int {
	dev.blocking = !nonblock
	return 0 /* Success */
}

func hid_send_feature_report(dev *hid_device, data string, length int) int {
	res := HidD_SetFeature(dev.device_handle, data, length)
	if !res {
		register_error(dev, "HidD_SetFeature")
		return -1
	}

	return length
}

func hid_get_feature_report(dev *hid_device, data string, length int) int {
	var res bool
	var bytes_returned uint32

	var ol OVERLAPPED

	res = DeviceIoControl(dev.device_handle,
		CTL_CODE(FILE_DEVICE_KEYBOARD, 100, METHOD_OUT_DIRECT, FILE_ANY_ACCESS),
		data, length,
		data, length,
		&bytes_returned, &ol)

	if !res {
		if GetLastError() != ERROR_IO_PENDING {
			/* DeviceIoControl() failed. Return error. */
			register_error(dev, "Send Feature Report DeviceIoControl")
			return -1
		}
	}

	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	res = GetOverlappedResult(dev.device_handle, &ol, &bytes_returned, true /*wait*/)
	if !res {
		/* The operation failed. */
		register_error(dev, "Send Feature Report GetOverLappedResult")
		return -1
	}

	/* bytes_returned does not include the first byte which contains the
	   report ID. The data buffer actually contains one more byte than
	   bytes_returned. */
	bytes_returned++

	return bytes_returned
}

func hid_close(dev *hid_device) {
	if dev == nil {
		return
	}
	CancelIo(dev.device_handle)
	free_hid_device(dev)
}

func hid_get_manufacturer_string(dev *hid_device, str *string, maxlen int) int {
	res := HidD_GetManufacturerString(dev.device_handle, str, intmin(maxlen, MAX_STRING_WCHARS))
	if !res {
		register_error(dev, "HidD_GetManufacturerString")
		return -1
	}
	return 0
}

func hid_get_product_string(dev *hid_device, str *string, maxlen int) int {
	res := HidD_GetProductString(dev.device_handle, str, intmin(maxlen, MAX_STRING_WCHARS))
	if !res {
		register_error(dev, "HidD_GetProductString")
		return -1
	}
	return 0
}

func hid_get_serial_number_string(dev *hid_device, str *string, maxlen int) int {
	res := HidD_GetSerialNumberString(dev.device_handle, str, intmin(maxlen, MAX_STRING_WCHARS))
	if !res {
		register_error(dev, "HidD_GetSerialNumberString")
		return -1
	}
	return 0
}

func hid_get_indexed_string(dev *hid_device, string_index int, str *string, maxlen int) int {
	res := HidD_GetIndexedString(dev.device_handle, string_index, str, intmin(maxlen, MAX_STRING_WCHARS))
	if !res {
		register_error(dev, "HidD_GetIndexedString")
		return -1
	}
	return 0
}

func hid_error(dev *hid_device) string {
	return dev.last_error_str
}

func intmin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

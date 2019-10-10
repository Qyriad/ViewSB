"""
USB libwireshark packet capture backend.


This file is part of ViewSB.
"""

import sys
import errno

from collections import defaultdict
from datetime import datetime

from .. import usb_types
from ..packet import USBSetupTransfer, USBStatusTransfer, USBDataTransfer, USBControlTransfer, \
    USBBulkTransfer, USBInterruptTransfer, USBTransferFragment, MalformedPacket, USBPacketID, USBDirection

from ..backend import ViewSBBackend

def eprint(s):
    sys.stderr.write(s + '\n')
    sys.stderr.flush()

try:
    import pyshark

    class ViewSBTSharkLiveCapture(pyshark.LiveCapture):
        """
        Due to an upstream issue with pyshark, (https://github.com/KimiNewt/pyshark/issues/320),
        it tries to use dumpcap on Windows, instead of USBPcap directly or just regular tshark,
        and doesn't start tshark with the right parameters.
        So we need to do some hacks to patch that out.
        These patches seem to result in the same behavior on Linux.
        """
        # FIXME: check macOS

        def get_parameters(self, packet_count=None):
            """ Overrides LiveCapture.get_parameters()
            `get_parameters` for LiveCapture's base class, Capture, is fine.
            But LiveCapture inserts `["-r", "-"]` into the parameters to get it to read from standard in,
            as it pipes dumpcap's output into the tshark process, but we're using tshark directly.
            """

            params = ['--disable-protocol', 'USBMS', '--disable-protocol', 'USB DFU', '--disable-protocol', 'USBAUDIO', '--disable-protocol', 'USBCCID', '--disable-protocol', 'USBCOM', '--disable-protocol', 'USBHID', '--disable-protocol', 'USBHUB', '--disable-protocol', 'USBIP', '--disable-protocol', 'USBPort', '--disable-protocol', 'USBVIDEO']
            params += pyshark.capture.capture.Capture.get_parameters(self, packet_count)
            for interface in self.interfaces:
                params += ["-i", interface]

            # Oh, also pyshark doesn't have an option for disabling specific protocols.

            return params

        async def _get_tshark_process(self, packet_count=None, stdin=None):
            """ Overrides LiveCapture.get_parameters()
            LiveCapture's version starts dumpcap in addition to tshark.
            """

            tshark = await pyshark.capture.capture.Capture._get_tshark_process(self, packet_count=packet_count, stdin=None)
            return tshark

except (ImportError, ModuleNotFoundError) as e:
    pass


class TSharkDriver:
    """ Generic class for using tshark. Overriden per platform. """

    TIMESTAMP_FORMAT = '%b %d, %Y %H:%M:%S.%f000 %Z'

    def __init__(self, backend, interface):
        sys.stderr.write('Initializing PyShark\n')
        sys.stderr.flush()

        self.backend = backend

        self.capture = ViewSBTSharkLiveCapture(interface, use_json=True, include_raw=True, debug=True)

    @classmethod
    def create_appropriate_backend(cls, backend, interface):
        for subclass in cls.__subclasses__():
            if subclass.supported():
                return subclass(backend, interface)

    @staticmethod
    def supported():
        raise NotImplementedError('This should be overriden in subclasses!')

    def _parse_tshark_packet(self, packet: pyshark.packet.packet.Packet):
        raise NotImplementedError('This should be overriden in a subclass!')

    def run(self):
        """ Continuously runs a tshark capture. """

        sys.stderr.write('Sniffing continuously…\n')
        sys.stderr.flush()

        for packet in self.capture.sniff_continuously():
            self._parse_tshark_packet(packet)


class LinuxTSharkDriver(TSharkDriver):

    URB_TRANSFER_TYPE_ISOCHRONOUS = 0x00
    URB_TRANSFER_TYPE_INTERRUPT   = 0x01
    URB_TRANSFER_TYPE_CONTROL     = 0x02
    URB_TRANSFER_TYPE_BULK        = 0x03

    URB_TYPE_SUBMIT   = "'S'"
    URB_TYPE_COMPLETE = "'C'"

    def __init__(self, *args, **kwargs):
        self.transfers = defaultdict(list)

        super().__init__(*args, **kwargs)

    @staticmethod
    def supported():
        return sys.platform.startswith('linux')

    def _build_control_transfer(self, request, response):

        urb_status = -int(request.usb.urb_status)
        request_timestamp = datetime.strptime(request.sniff_timestamp, self.TIMESTAMP_FORMAT)

        # tshark doesn't give us the fields with generic names (wValue and wIndex) if it knows what they mean
        # (like for GET_DESCRIPTOR requests), so we'll just grab the bytes ourselves.
        # Setup data is always 8 bytes long, and in tshark it seems to start 40 bytes into the USB_RAW layer.
        setup_data = bytes.fromhex(request.usb_raw.value)[40:48]
        setup_transfer = USBSetupTransfer.from_setup_data(setup_data, timestamp=request_timestamp)
        setup_transfer.validate()

        # With no setup data, the response is a little harder.
        # The actual data sent seems to start 64 bytes into the FRAME_RAW layer, and take up the rest of the layer.
        response_data = bytes.fromhex(response.frame_raw.value)[64:]
        response_timestamp = datetime.strptime(response.sniff_timestamp, self.TIMESTAMP_FORMAT)
        response_transfer = USBDataTransfer(data=response_data, timestamp=response_timestamp, direction=setup_transfer.direction.reverse())
        response_transfer.validate()

        status = -int(response.usb.urb_status)
        if status is errno.EPIPE:
            pid = USBPacketID.STALL
        else:
            pid = USBPacketID.ACK

        status_transfer = USBStatusTransfer(pid=pid, timestamp=response_timestamp, direction=setup_transfer.direction.reverse())

        control_transfer = USBControlTransfer.from_subordinates(setup_transfer, response_transfer, status_transfer)
        control_transfer.validate()
        self.backend.emit_packet(control_transfer)

        # Delete all transfers with the same ID, since we've hopefully just handled them.
        del self.transfers[request['USB'].urb_id]

    def _build_interrupt_or_bulk_transfer(self, request, response):
        # Bulk and interrupt transfers.

        data_packet = None
        data = None

        request_length = int(request.usb.data_len)
        response_length = int(response.usb.data_len)

        if request_length:
            data_packet = request
        elif response_length:
            data_packet = response

        urb_status = abs(int(response.usb.urb_status))
        timestamp = datetime.strptime(request.sniff_timestamp, self.TIMESTAMP_FORMAT)
        handshake = None
        direction = USBDirection.from_endpoint_address(int(request['USB'].endpoint_address, 16))

        if urb_status is 0:
            handshake = USBPacketID.ACK
        elif urb_status is errno.EPIPE:
            handshake = USBPacketID.STALL
        else:
            # FIXME: The urb status may have meaningful data we can extract.

            self.backend.emit_packet(MalformedPacket(
                data=data, timestamp=timestamp, handshake=handshake, direction=direction))
            del self.transfers[request['USB'].urb_id]
            return

        if data_packet:
            length = int(data_packet.usb.data_len)
            data = bytes.fromhex(data_packet['usb.capdata_raw'].value)

        # FIXME: code duplication.
        if transfer_type == self.URB_TRANSFER_TYPE_BULK:

            self.backend.emit_packet(USBBulkTransfer(
                data=data, timestamp=timestamp, handshake=handshake, direction=direction))
            del self.transfers[request['USB'].urb_id]

        elif transfer_type == self.URB_TRANSFER_TYPE_INTERRUPT:

            self.backend.emit_packet(USBInterruptTransfer(
                data=data, timestamp=timestamp, handshake=handshake, direction=direction))
            del self.transfers[request['USB'].urb_id]


    def _build_viewsb_packet_from_urbs(self, request, response):

        if not request:

            # FIXME: the response might have meaningful data, which we should emit.

            del self.transfers[response['USB'].urb_id]

            return

        if not response:

            # FIXME: the request might have meaningful data, which we should emit.

            del self.transfers[request['USB'].urb_id]

            return

        transfer_type = int(request['USB'].transfer_type, base=16)

        if transfer_type == self.URB_TRANSFER_TYPE_CONTROL:
            self._build_control_transfer(request, response)

        elif transfer_type != self.URB_TRANSFER_TYPE_ISOCHRONOUS:
            self._build_interrupt_or_bulk_transfer(request, response)

        else:

            # XXX: FIXME: implement isochronous transfers.
            pass

    def _parse_tshark_packet(self, packet: pyshark.packet.packet.Packet):
        """ Overrides TSharkDriver._parse_tshark_packet(). """


        # Each packet will have an URB ID, which we can use to keep track of transfers.
        # The URB ID is found in the USB Layer of the packet.
        urb_id = packet['USB'].urb_id
        self.transfers[urb_id] += [packet]

        request = next((x for x in self.transfers[urb_id] if x['USB'].urb_type == self.URB_TYPE_SUBMIT), None)
        response = next((x for x in self.transfers[urb_id] if x['USB'].urb_type == self.URB_TYPE_COMPLETE), None)

        # XXX: XXX: XXX

        if request and response:
            self._build_viewsb_packet_from_urbs(request, response)


class WindowsTSharkDriver(TSharkDriver):

    USBPCAP_TRANSFER_CONTROL = 0x02

    @staticmethod
    def supported():
        return sys.platform.startswith('win32')


class TSharkBackend(ViewSBBackend):
    """
    Class that handles data from tshark.
    """

    UI_NAME = "tshark"
    UI_DESCRIPTION = "tshark software analyzers"


    # @staticmethod
    # def reason_to_be_disabled():
        # # FIXME:
        # return True

    def __init__(self, interface='usbmon5'):
        """ `interface`: the interface from which to capture, like `usbmon0`. """

        sys.stderr.write('Initializing PyShark\n')
        sys.stderr.flush()
        self.tshark_driver = TSharkDriver.create_appropriate_backend(self, interface)

        if self.tshark_driver is None:
            raise IOError('No backend for this platform is available!')

        self.transfers = defaultdict(list)

    def run(self):
        """ Continuously runs a tshark capture. """

        self.tshark_driver.run()

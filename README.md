09-JULY-2017 Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>

The openHPSDR Plug-in for Wireshark is written to disassemble the openHPSDR
Ethernet protocol.

The protocol is still under development.

The current public released protocol documentation list located at:
https://github.com/TAPR/OpenHPSDR-Firmware/tree/master/Protocol%202/Documentation

Version 0.0.6:
  - Wireshark version 2.2.3
  - Updated to version 3.5 of protocol documentation.
  - Corrected and cleaned up High Priority Command (HPC) Alex0 register map
    bits.
  - Tested and verified set IP address and firmware programing.
  - Cleaned up Command Reply (CR) Hardware Erase Acknowledgment / Complete.
  - Cleaned up Command Reply (CR) Hardware Program Reply / Acknowledgment.
  - Removed "Program Check Roll Over" test. The last program block from the host
    is padded. The packet length test will discover what the removed test was
    trying to discover.
  - Added Orion MkII (ANAN-8000DLE) details.
    - Command Reply (CR):
      - Added to Discovery reply
    - High Priority Status (HP):
      - Change label for bits 0 to 4 of byte 59.
    - High Priority Command (HPC):
       - Added text string listing Alex0 register map bits not used by
         Orion MkII (ANAN-8000DLE).
       - Added Alex0 TX RX Orion MkII (ANAN-8000DLE) status bit.
       - Added bit 1400: Transverter Enable, IO1 Audio state.

-------------------------------------------------------------------------------


General Notes
-------------
I have done basic testing of the plug-in with the Hermes firmware version 10.3.

I have done basic testing with:
Thetis (v2.5.2 7/9/17 beta)
Web Server version of HPSDR Programmer Version 0.2.8

Non-default Ports
-----------------
The plug in does support using service ports other then the default service
ports. The plug in needs to see the non-default ports in a
Command Reply (CR) General datagram before it will correctly disassemble
traffic using non-default ports.


Protocol Datagrams
------------------
The openHPSDR Ethernet protocol is comprised of eleven different datagram
formats. Below is a table that lists the default ports and the protocol names
and abbreviation that I use in the WireShark dissector. Traffic originated by
the host uses the port number as the UDP destination port. Traffic originated
by the hardware uses the port as the source UDP port.

The name below are not the same as the in the protocol documentation. These
are names that I created.

   Host and Hardware Use the Same Port
   -----------------------------------
   Port   Name
   1024   Command Reply (CR)
   xxxx   Memory Mapped (MEM)

   Host to Hardware - destination UDP port
   ---------------------------------------
   1025 	DDC Command (DDCC)
   1026 	DUC Command (DUCC)
   1027 	High Priority Command (HPC)
   1028 	DDC Audio (DDCA)
   1029 to 1036	DUC I&Q Data (DUCIQ)

   Hardware to Host -source UDP port
   ---------------------------------
   1025		High Priority Status (HPS)
   1026		Mic / Line Samples (MICL)
   1027 to 1034	Wide Band Data (WBD)
   1035 to 1114	DDC I&Q Data (DDCIQ)



Plug In Preferences
-------------------
There are three configurable preferences in the WireShark dissector.

They are all boolean (on or off) preferences.

-"Strict Checking of Datagram Size"
  Disable checking for added bytes at the end of the datagrams.
  Turning off disables a warning meassge.

-"Strict Pad Checking"
  Strict checking of the amount of pad bytes at the end of the datagrams.
  When enabled, Wireshark (not the openHPSDR dissector) will display
  a "Malformed Packet" error for a datagram without the correct
  number of pad bytes.
  When disabled, checking is only for one pad byte instead of checking
  for the correct number of pad bytes.

-"ddciq_iq_mtu_check"
 Check to see if the number of I&Q Samples
 will exceed the maximum Ethernet MTU (1500 bytes).
 When disabled, there will be no checking
 to see if the MTU will be exceeded.


Display Filters
---------------
In Wireshark you can filter packets by using display filters. The display
filtersuse fields that are created when the packets are disassembled. I tried to
addfields for every thing in the protocol except the samples (audio, I&Q) and
mapped memory (address, data).

The samples and mapped memory have a repetitive format. I created a index field
for these datagrams. A few examples are below.

Here is an example display filter for finding a Mic / Line Samples (MICL)
datagrams.

openhpsdr-e.micl.sample-idx==718 && openhpsdr-e.micl.sample == 0x1111
-Find all the MICL datagrams in which sample number 718 has a value of 0x1111.

Here is an example display filter for finding Wide Band (WBD) datagrams.

openhpsdr-e.wbd.adc == 4 && openhpsdr-e.wbd.sample-idx == 2 && openhpsdr-e.wbd.sample == 0x66ee
-Find all WDB datagrams from ADC number 4 in which sample number 2 has the value
of 0x66ee.

The easiest way to find a field name is to click on a item in Wireshark. The
field label will appear on the bottom of the Wireshark window. All the field
labels start with "openhpsdr-e." . You can also click on the bytes in the raw
display to select the field labels.


Known Issues
------------
There is one known issue. Switching, in the same capture, from a non-default
port to default a default port, in a Command Reply (CR) General datagram,  can
cause Wireshark to crash. The default port numbers where explicitly specified
in the CR General datagram datagram. They where not set to "0". Zero is the
datagrams also mean use the default ports.  The cause of the issue may be a fix
I implemented to allow for columns to added and deleted.

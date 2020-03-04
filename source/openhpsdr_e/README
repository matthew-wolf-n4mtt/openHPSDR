09-May-2019 Matthew J. Wolf Email: matthew.wolf.hpsdr at speciosus.net

The openHPSDR Plug-in for Wireshark is written to disassemble the openHPSDR
Ethernet protocol. The protocol is also is referred to as "Protocol 2".

The protocol is still under development.

The current public released protocol documentation list located at:
https://github.com/TAPR/OpenHPSDR-Firmware/tree/master/Protocol%202/Documentation

Version 0.0.7.1
  - Due to issue with the Microsoft Windows build. The "-"
    in the source file system names has been replaced with "_".

Version 0.0.7:
  - Wireshark version 3.0.1
  - Changed source file names from openhpsdr to openhpsdr-e.
  - Added references for Protocol 2 to text strings. 
    -- Added "P2" to the heuristic dissectors display_name.
    -- New Name: "OpenHPSDR Ethernet - Protocol 2"
    -- New Short Name: "HPSDR-ETH_P2"
    -- No change to Abbreviation: "hpsdr-e" 
  - Fixed the location of line in gain in DUC Command (DUCC), byte 51.
  - In High Priority Command (HPC)
     -- Removed the non-existing 8th open collector.
     -- Moved CWX0 into a sub menu.
     -- changed fields:
        openhpsdr-e.hpc.cwx0    is now openhpsdr-e.hpc.cwx0-cwx
        openhpsdr-e.hpc.cw-dot  is now openhpsdr-e.hpc.cwx0-dot
        openhpsdr-e.hpc.cw-dash is now openhpsdr-e.hpc.cwx0-dash
 - Fixed incorrect multiple use of the same field:
  -- openhpsdr-e.cr.discovery.mac
    --- Added fields:
        openhpsdr-e.cr.erase.mac
        openhpsdr-e.cr.program.mac
  -- openhpsdr-e.cr.discovery.board
    --- Added fields:
        openhpsdr-e.cr.erase.board
        openhpsdr-e.cr.program.board
  -- openhpsdr-e.cr.discovery.proto-ver
    --- Added field:
        openhpsdr-e.cr.erase.proto-ver
  - Version 3.7 Changes
    --In High Priority Status (HPS) added text string to warn about DUC I&Q FIFO
      almost full and almost empty are no longer supported as of version 3.7
      of the protocol.
      --- Should they be removed at some point in the future?
     -- Removed Multiplexed Mode
        --- In DUC Command (DUCC) changed DDC Multiplex sub menu to a warning
            text string.
	--- In Command Reply (CR) Hardware Discovery Reply for Full Hardware
	    Description. DDC Multiplex changed to a warning text string.
  - Version 3.8 changes
    -- The DUC Command (DUCC) byte 6, CW side tone level, is definded as a 7
       bit value. Added a bit mask so that the last bit is not displayed.   
    -- Open collector numbering changed from starting at 0 to starting at 1.
    -- Added Beta Version to Command Reply (CR). 
    -- Changed the format of the Command Reply (CR) Hardware "Response
       to Program"


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
and abbreviation that I use in the Wireshark dissector. Traffic originated by
the host uses the port number as the UDP destination port. Traffic originated
by the hardware uses the port as the source UDP port.

The name below are not the same as the in the protocol documentation. These
are names that I created.

 Host and Hardware Use the Same Port
 -----------------------------------
- Port   Name
- 1024   Command Reply (CR)
- xxxx   Memory Mapped (MEM)

 Host to Hardware - destination UDP port
 ---------------------------------------
- 1025 	DDC Command (DDCC)
- 1026 	DUC Command (DUCC)
- 1027 	High Priority Command (HPC)
- 1028 	DDC Audio (DDCA)
- 1029 to 1036	DUC I&Q Data (DUCIQ)

 Hardware to Host -source UDP port
 ---------------------------------
- 1025		High Priority Status (HPS)
- 1026		Mic / Line Samples (MICL)
- 1027 to 1034	Wide Band Data (WBD)
- 1035 to 1114	DDC I&Q Data (DDCIQ)



Plug In Preferences
-------------------
There are three configurable preferences in the Wireshark dissector.

They are all Boolean (on or off) preferences.

- "Strict Checking of Datagram Size"
  Disable checking for added bytes at the end of the datagrams.
  Turning off disables a warning message.

- "Strict Pad Checking"
  Strict checking of the amount of pad bytes at the end of the datagrams.
  When enabled, Wireshark (not the openHPSDR dissector) will display
  a "Malformed Packet" error for a datagram without the correct
  number of pad bytes.
  When disabled, checking is only for one pad byte instead of checking
  for the correct number of pad bytes.

- "ddciq_iq_mtu_check"
 Check to see if the number of I&Q Samples
 will exceed the maximum Ethernet MTU (1500 bytes).
 When disabled, there will be no checking
 to see if the MTU will be exceeded.


Display Filters
---------------
In Wireshark you can filter packets by using display filters. The display
filters use fields that are created when the packets are disassembled. I tried to
add fields for every thing in the protocol except the samples (audio, I&Q) and
mapped memory (address, data).

The samples and mapped memory have a repetitive format. I created a index field
for these datagrams. A few examples are below.

Here is an example display filter for finding a Mic / Line Samples (MICL)
datagrams.

openhpsdr-e.micl.sample-idx==718 && openhpsdr-e.micl.sample == 0x1111
- Find all the MICL datagrams in which sample number 718 has a value of 0x1111.

Here is an example display filter for finding Wide Band (WBD) datagrams.

openhpsdr-e.wbd.adc == 4 && openhpsdr-e.wbd.sample-idx == 2 && openhpsdr-e.wbd.sample == 0x66ee
- Find all WDB datagrams from ADC number 4 in which sample number 2 has the value
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

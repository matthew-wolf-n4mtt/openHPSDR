/* packet-openhpsdr.c  
 * Routines for the OpenHPSDR Ethernet protocol packet disassembly
 *
 * This file is part of the OpenHPSDR Plug-in for Wireshark.
 * By Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
 * Copyright 2016 Matthew J. Wolf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * The HPSDR-USB Plug-in for Wireshark is free software: you can 
 * redistribute it and/or modify it under the terms of the GNU 
 * General Public License as published by the Free Software Foundation,
 * either version 2 of the License, or (at your option) any later version.
 * 
 * The HPSDR-USB Plug-in for Wireshark is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the HPSDR-USB Plug-in for Wireshark.  
 * If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * The HPSDR-USB Plug-in for Wireshark is written to disassemble the protocol
 * that is defined in the documents listed below.
 *
 * The protocol is still under development. 
 * 
 * The current public released protocol documentation list located at:
 * http://svn.tapr.org/repos_sdr_hpsdr/trunk/Angelia_new_protocol/Documentation/
 *
 * DDC - Digital Down Converter 
 * DUC - Digital Up Converter
 *
 */

// cr    - Command Reply (port 1024)
// ddcc  - DDC Command (Host to Hardware - dest port 1025)
// hps   - High Priority Status (Hardware to Host - source port 1025)
// ducc  - DUCC Command (Host to Hardware - dest port 1026)
// micl  - Mic / Line Samples (Hardware to Host - source port 1026)
// hpc   - High Priority Command (Host to Hardware - dest port 1027)
// wbd   - Wide Data (Hardware to Host - base source port 1027)
// ddca	 - DDC Audio (Host to Hardware - dest port 1028) 
// duciq - DUC I&Q Data (Host to Hardware - base dest port 1029)
// ddciq - DDC I&Q Data (Hardware to Host - base source port 1035)
// mem   - Memory Mapped (No default port)

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "packet-openhpsdr.h"


//Port definitions in packet-openhpsdr.h header


//nameing: "From-Host From-Hardware"
// Port   Name
// 1024   Command Reply (cr) 
// xxxx   Memory Mapped (mem) 

// Host to Hardware
// 1025   DDC Command (ddcc)
// 1026   DUC Command (ducc)
// 1027   High Priority Command (hpc)
// 1028   DDC Audio Base Port (ddca)
// 1029   DUC I&Q Data Base Port (duciq)

// Hardware to Host
// 1025   High Priority Status (hps)
// 1026   Mic / Line Samples (micl)
// 1027   Wide Band Base Port (wbd)
// 1035   DDC I&Q Data (ddciq)

// Protocol Variables
static int proto_openhpsdr_e = -1;

// Subtree State Variables
// - Using two letter abbreviations for protocol type.
// cr    - Command Reply (port 1024)
// ddcc  - DDC Command (Host to Hardware - dest port 1025)
// hps   - High Priority Status (Hardware to Host - source port 1025)
// ducc  - DUC Command (Host to Hardware - dest port 1026)
// micl  - Mic / Line Samples (Hardware to Host - source port 1026)
// hpc   - High Priority Command (Host to Hardware - dest port 1027)
// wbd   - Wide Band Data (Hardware to Host - base source port 1027)
// ddca  - DDC Audio (Host to Hardware - dest port 1028)
// duciq - DUC I&Q Data (Host to Hardware - base dest port 1029)
// ddciq - DDC I&Q Data (Hardware to Host - base source port 1035)
// mem   - Memory Mapped (No default port)
static gint ett_openhpsdr_e_cr = -1;
static gint ett_openhpsdr_e_ddcc = -1;
static gint ett_openhpsdr_e_hps = -1;
static gint ett_openhpsdr_e_ducc = -1;
static gint ett_openhpsdr_e_micl = -1;
static gint ett_openhpsdr_e_hpc = -1;
static gint ett_openhpsdr_e_wbd = -1;
static gint ett_openhpsdr_e_ddca = -1;
static gint ett_openhpsdr_e_duciq = -1;
static gint ett_openhpsdr_e_ddciq = -1;
static gint ett_openhpsdr_e_mem = -1;

// Fields
// - Using two letter abbreviations for protocol type. 
// cr    - Command Reply (port 1024)
// ddcc  - DDC Command (Host to Hardware - dest port 1025)
// hps   - High Priority Status (Hardware to Host - source port 1025)
// ducc  - DUC Command (Host to Hardware - dest port 1026)
// micl  - Mic / Line Samples (Hardware to Host - source port 1026)
// hpc   - High Priority Command (Host to Hardware - dest port 1027)
// wbd   - Wide Band Data (Hardware to Host - base source port 1027)
// ddca  - DDC Audio (Host to Hardware - dest port 1028)
// ddca  - DDC Audio (Host to Hardware - dest port 1028)
// duciq - DUC I&Q Data (Host to Hardware - base dest port 1029)
// ddciq - DDC I&Q Data (Hardware to Host - base source port 1035)
// mem   - Memory Mapped (No default port)

static int hf_openhpsdr_e_reserved = -1;

static int hf_openhpsdr_e_cr_banner = -1;
static int hf_openhpsdr_e_cr_sequence_num = -1;
static int hf_openhpsdr_e_cr_command = -1;
static int hf_openhpsdr_e_cr_ei = -1;
static int hf_openhpsdr_e_cr_pad = -1;
static int hf_openhpsdr_e_cr_desc = -1;
static int hf_openhpsdr_e_cr_disc_mac = -1;
static int hf_openhpsdr_e_cr_disc_board = -1;
static int hf_openhpsdr_e_cr_disc_proto_ver = -1;
static int hf_openhpsdr_e_cr_disc_fw_ver = -1;
static int hf_openhpsdr_e_cr_disc_merc0_ver = -1;
static int hf_openhpsdr_e_cr_disc_merc1_ver = -1;
static int hf_openhpsdr_e_cr_disc_merc2_ver = -1;
static int hf_openhpsdr_e_cr_disc_merc3_ver = -1;
static int hf_openhpsdr_e_cr_disc_penny_ver = -1;
static int hf_openhpsdr_e_cr_disc_metis_ver = -1;
static int hf_openhpsdr_e_cr_disc_ddc_num = -1;
static int hf_openhpsdr_e_cr_disc_freq_phase = -1;
static int hf_openhpsdr_e_cr_prog_blocks = -1;
static int hf_openhpsdr_e_cr_prog_data = -1;
static int hf_openhpsdr_e_cr_setip_sub = -1;
static int hf_openhpsdr_e_cr_setip_mac = -1;
static int hf_openhpsdr_e_cr_setip_ip = -1;
static int hf_openhpsdr_e_cr_gen_ddcc_port = -1;
static int hf_openhpsdr_e_cr_gen_ducc_port = -1;
static int hf_openhpsdr_e_cr_gen_hpc_port = -1;
static int hf_openhpsdr_e_cr_gen_hps_port = -1;
static int hf_openhpsdr_e_cr_gen_ddca_port = -1;
static int hf_openhpsdr_e_cr_gen_duciq_base_port = -1;
static int hf_openhpsdr_e_cr_gen_ddciq_base_port = -1;
static int hf_openhpsdr_e_cr_gen_micl_port = -1;
static int hf_openhpsdr_e_cr_gen_wbd_base_port = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_0 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_1 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_2 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_3 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_4 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_5 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_6 = -1;
static int hf_openhpsdr_e_cr_gen_wb_en_7 = -1;
static int hf_openhpsdr_e_cr_gen_wb_samples = -1;
static int hf_openhpsdr_e_cr_gen_wb_size = -1;
static int hf_openhpsdr_e_cr_gen_wb_rate = -1;
static int hf_openhpsdr_e_cr_gen_wb_datagrams_full_spec = -1;
static int hf_openhpsdr_e_cr_gen_mem_host_port = -1;
static int hf_openhpsdr_e_cr_gen_mem_hw_port = -1;
static int hf_openhpsdr_e_cr_gen_pwm_env_min = -1;
static int hf_openhpsdr_e_cr_gen_pwm_env_max = -1;
static int hf_openhpsdr_e_cr_gen_iq_ts = -1;
static int hf_openhpsdr_e_cr_gen_vita = -1;
static int hf_openhpsdr_e_cr_gen_vna = -1;
static int hf_openhpsdr_e_cr_gen_freq_phase = -1;
static int hf_openhpsdr_e_cr_gen_atlas_merc_cfg = -1;
static int hf_openhpsdr_e_cr_gen_10mhz = -1;
static int hf_openhpsdr_e_cr_gen_pa = -1;
static int hf_openhpsdr_e_cr_gen_apollo_atu_auto = -1;
static int hf_openhpsdr_e_cr_gen_merc_comm_freq = -1;
static int hf_openhpsdr_e_cr_gen_122880khz = -1;
static int hf_openhpsdr_e_cr_gen_alex_0 = -1;
static int hf_openhpsdr_e_cr_gen_alex_1 = -1;
static int hf_openhpsdr_e_cr_gen_alex_2 = -1;
static int hf_openhpsdr_e_cr_gen_alex_3 = -1;
static int hf_openhpsdr_e_cr_gen_alex_4 = -1;
static int hf_openhpsdr_e_cr_gen_alex_5 = -1;
static int hf_openhpsdr_e_cr_gen_alex_6 = -1;
static int hf_openhpsdr_e_cr_gen_alex_7 = -1;

static int hf_openhpsdr_e_ddcc_banner = -1; 
static int hf_openhpsdr_e_ddcc_sequence_num = -1;

static int hf_openhpsdr_e_hps_banner = -1;
static int hf_openhpsdr_e_hps_sequence_num = -1;

static int hf_openhpsdr_e_ducc_banner = -1;
static int hf_openhpsdr_e_ducc_sequence_num = -1;

static int hf_openhpsdr_e_micl_banner = -1;
static int hf_openhpsdr_e_micl_sequence_num = -1;

static int hf_openhpsdr_e_hpc_banner = -1;
static int hf_openhpsdr_e_hpc_sequence_num = -1;

static int hf_openhpsdr_e_wbd_banner = -1;
static int hf_openhpsdr_e_wbd_sequence_num = -1;

static int hf_openhpsdr_e_ddca_banner = -1;
static int hf_openhpsdr_e_ddca_sequence_num = -1;

static int hf_openhpsdr_e_duciq_banner = -1;
static int hf_openhpsdr_e_duciq_sequence_num = -1;

static int hf_openhpsdr_e_ddciq_banner = -1;
static int hf_openhpsdr_e_ddciq_sequence_num = -1;

static int hf_openhpsdr_e_mem_banner = -1;
static int hf_openhpsdr_e_mem_sequence_num = -1;

// Expert Items
static expert_field ei_cr_extra_length = EI_INIT;
static expert_field ei_cr_program_check_roll_over = EI_INIT;

// Preferences
static gboolean openhpsdr_e_strict_size = TRUE;
static gboolean openhpsdr_e_strict_pad = TRUE;
static gboolean openhpsdr_e_cr_strict_program_data_size = TRUE;

//Tracking Variables 
static guint16 openhpsdr_e_cr_ddcc_port = -1;
static guint16 openhpsdr_e_cr_hps_port = -1;
static guint16 openhpsdr_e_cr_ducc_port = -1;
static guint16 openhpsdr_e_cr_micl_port = -1;
static guint16 openhpsdr_e_cr_hpc_port = -1;
static guint16 openhpsdr_e_cr_wbd_base_port = -1;
static guint16 openhpsdr_e_cr_ddca_port = -1;
static guint16 openhpsdr_e_cr_duciq_base_port = -1;
static guint16 openhpsdr_e_cr_ddciq_base_port = -1;
static guint16 openhpsdr_e_cr_mem_host_port = -1;
static guint16 openhpsdr_e_cr_mem_hw_port = -1;

static const value_string cr_disc_board_id[] = {
    { 0x00, "Atlas" },
    { 0x01, "\"Hermes\" (ANAN-10,100)" },
    { 0x02, "\"Hermes\" (ANAN-10E, 100B)" },
    { 0x03, "\"Angela\" (ANAN-100D)" },
    { 0x04, "\"Orion\" (ANAN-200D)" },
    { 0x05, "Reserved" },
    { 0x06, "Hermes Lite" }, 
    { 0x07, "Reserved" },
    { 0x08, "Reserved" },
    { 0x09, "Reserved" },
    { 0xFE, "XML Hardware Description" },
    { 0xFF, "Full Hardware Description" },
    {0, NULL}
};

static const value_string cr_gen_atlas_merc[] = {
    { 0x00, "Single DDC" }, // 0b000
    { 0x01, "Two DDCs" },   // 0b001
    { 0x02, "Three DDCs" }, // 0b010
    { 0x03, "Four DDCs" },  // 0b011
    {0, NULL}
};

static const value_string cr_gen_10mhz[] = {
    { 0x00, "Atlas / Excalibur" },
    { 0x01, "Penelope" },
    { 0x02, "Mercury" },
    {0, NULL}
};

static const  true_false_string phase_freq = {
    "Phase",          // when true  (1)
    "Frequency"       // when false (0)
};

static const true_false_string mercury_penelope = {
    "Mercury",
    "Penelope"
};

static const true_false_string same_independent = {
    "Same",
    "Independent"
};

// The Windows build environment does not like to pull in the
// true_false_string structures from Wireshark source / dll 
// tfs.c. The true_false_string structure is defined in tfs.h.
// Tfs.h is pulled in via packet.h. 
// The true_false_string structures below are duplicates of 
// structures found in tfs.c
//const true_false_string local_active_inactive = { "Active", "Inactive" };
//const true_false_string local_set_notset = { "Set", "Not set" };
//const true_false_string local_on_off = { "On", "Off" };
const true_false_string local_enabled_disabled = { "Enabled", "Disabled" };
//const true_false_string local_disabled_enabled = { "Disabled", "Enabled" };



// Using two letter abbreviations for protocol type.
// cr - Command Reply (port 1024)
// ddcc - DDC Command (Host to Hardware - dest port 1025)
// hps  - High Priority Status (Hardware to Host - source port 1025)
// ducc - DUC Command (Host to Hardware - dest port 1026)
// hpc  - High Priority Command (Host to Hardware - dest port 1027)
// ddca - DDC Audio (Host to Hardware - dest port 1028)
// duciq - DUC I&Q Data (Host to Hardware - base dest port 1029)
// ddciq - DDC I&Q Data (Hardware to Host - base source port 1035)
// mem   - Memory Mapped (No default port)
void 
proto_register_openhpsdr_e(void)
{
   module_t *openhpsdr_e_prefs;
   expert_module_t *expert_openhpsdr_e_cr;

   // Subtree Array
   static gint *ett[] = {
        &ett_openhpsdr_e_cr,
        &ett_openhpsdr_e_ddcc,
        &ett_openhpsdr_e_hps,
        &ett_openhpsdr_e_ducc,
        &ett_openhpsdr_e_micl,
        &ett_openhpsdr_e_hpc,
        &ett_openhpsdr_e_wbd,
        &ett_openhpsdr_e_ddca,
        &ett_openhpsdr_e_duciq,
        &ett_openhpsdr_e_ddciq,
        &ett_openhpsdr_e_mem
   };

   // Protocol expert items 
   static ei_register_info ei_cr[] = {
       { &ei_cr_extra_length,
           { "openhpsdr-e.ei.cr.extra-length", PI_MALFORMED, PI_WARN,
             "Extra Bytes", EXPFILL }
       },
       { &ei_cr_program_check_roll_over,
           { "openhpsdr-e.ei.cr.program-check-roll-over", PI_MALFORMED, PI_WARN,
             "Program Roll Over Check", EXPFILL }
       },

   };

    //Field Arrary 
    static hf_register_info hf[] = {
       { &hf_openhpsdr_e_reserved,
           { "Reserved for Future Use" , "openhpsdr-e.reserved",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
    };


    // Command Reply Field Arrary
    static hf_register_info hf_cr[] = {
       { &hf_openhpsdr_e_cr_banner,
           { "openHPSDR Ethernet - Command Reply" , "openhpsdr-e.cr.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_sequence_num,
           { "Sequence Number", "openhpsdr-e.cr.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_command,
           { "Command", "openhpsdr-e.cr.command",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_ei,
           { "CR Expert" , "openhpsdr-e.cr.ei",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_pad,
           { "Zero Pad" , "openhpsdr-e.cr.zero",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_desc,
           { "DC Description" , "openhpsdr-e.cr.desc",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_mac,
           { "Board MAC Address" , "openhpsdr-e.cr.discovery.mac",
            FT_ETHER, BASE_NONE,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_board,
           { "Board Type", "openhpsdr-e.cr.discovery.board",
            FT_UINT8, BASE_DEC,
            VALS(cr_disc_board_id), ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_proto_ver,
           { "Supported Potocol Version", "openhpsdr-e.cr.discovery.proto-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_fw_ver,
           { "Firmware Version", "openhpsdr-e.cr.discovery.fw-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_merc0_ver,
           { "Mercury0 Version", "openhpsdr-e.cr.discovery.merc0-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_merc1_ver,
           { "Mercury1 Version", "openhpsdr-e.cr.discovery.merc1-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_merc2_ver,
           { "Mercury2 Version", "openhpsdr-e.cr.discovery.merc2-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_merc3_ver,
           { "Mercury3 Version", "openhpsdr-e.cr.discovery.merc3-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_penny_ver,
           { "Penny   Version ", "openhpsdr-e.cr.discovery.penny-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_metis_ver,
           { "Metis   Version ", "openhpsdr-e.cr.discovery.metis-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_ddc_num,
           { "Number of DDC Implemented", "openhpsdr-e.cr.discovery.metis-ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_disc_freq_phase,
           { "Frequency or Phase Word" , "openhpsdr-e.cr.discovery.freq-phase", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&phase_freq), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_prog_blocks,
           { "Program Blocks", "openhpsdr-e.cr.program.blocks",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_prog_data,
           { "Program Blocks", "openhpsdr-e.cr.program.data",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
      { &hf_openhpsdr_e_cr_setip_sub,
           { "CR Program Submenu" , "openhpsdr-e.cr.setip.sub",
            FT_UINT8, BASE_HEX,
            NULL, BIT8_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_setip_mac,
           { "Set IP - MAC Address" , "openhpsdr-e.cr.setip.mac",
            FT_ETHER, BASE_NONE,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_openhpsdr_e_cr_setip_ip,
           { "Set IP -  IP Address" , "openhpsdr-e.cr.setip.ip",
            FT_IPv4, BASE_NETMASK,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_ddcc_port,
           { "      DDC  Command  Port     " , "openhpsdr-e.cr.gen.ddcc-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_ducc_port,
           { "      DUC  Command  Port     " , "openhpsdr-e.cr.gen.ducc-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_hpc_port,
           { "  High Priority Command Port " , "openhpsdr-e.cr.gen.hpc-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_hps_port,
           { "  High Priority  Status Port " , "openhpsdr-e.cr.gen.hps-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_ddca_port,
           { "      DDC   Audio   Port     " , "openhpsdr-e.cr.gen.ddca-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_duciq_base_port,
           { "      DUC  Base IQ  Port     " , "openhpsdr-e.cr.gen.duciq-base-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_ddciq_base_port,
           { "      DDC  Base IQ  Port     " , "openhpsdr-e.cr.gen.ddciq-base-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_micl_port,
           { "     Mic / Line Samples Port " , "openhpsdr-e.cr.gen.micl-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wbd_base_port,
           { "     Wideband Data Base Port " , "openhpsdr-e.cr.gen.wbd-base-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_0,
           { " Wideband 0 State" , "openhpsdr-e.cr.gen.wb0-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_1,
           { " Wideband 1 State" , "openhpsdr-e.cr.gen.wb1-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_2,
           { " Wideband 2 State" , "openhpsdr-e.cr.gen.wb2-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_3,
           { " Wideband 3 State" , "openhpsdr-e.cr.gen.wb3-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_4,
           { " Wideband 4 State" , "openhpsdr-e.cr.gen.wb4-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_5,
           { " Wideband 5 State" , "openhpsdr-e.cr.gen.wb5-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_6,
           { " Wideband 6 State" , "openhpsdr-e.cr.gen.wb6-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_en_7,
           { " Wideband 7 State" , "openhpsdr-e.cr.gen.wb7-state", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_samples,
           { "Wideband Samples per Datagram" , "openhpsdr-e.cr.gen.wb-samples",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_size,
           { "Wideband Samples Size        ", "openhpsdr-e.cr.cr.gen.wb-size",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_rate,
           { "Wideband Samples Rate        ", "openhpsdr-e.cr.cr.gen.wb-rate",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_wb_datagrams_full_spec,
           { "Datagrams for Full Wideband Spectrum", "openhpsdr-e.cr.cr.gen.wb-datagrams-full",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_mem_host_port,
           { "  Memory Mapped     Host Port" , "openhpsdr-e.cr.gen.mem-host-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_mem_hw_port,
           { "  Memory Mapped Hardware Port" , "openhpsdr-e.cr.gen.mem-hw-port",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_pwm_env_min,
           { "         PWM Envelope Minimum" , "openhpsdr-e.cr.gen.pwm-env-min",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_pwm_env_max,
           { "         PWM Envelope Maximum" , "openhpsdr-e.cr.gen.pwm-env-max",
            FT_UINT16, BASE_DEC,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_iq_ts,
           { "Time Stamp DDC IQ" , "openhpsdr-e.cr.gen.iq-ts", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_vita,
           { "   VITA-49 Format" , "openhpsdr-e.cr.gen.vita", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_vna,
           { "         VNA Mode" , "openhpsdr-e.cr.gen.vna", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_freq_phase,
           { "DDC & DUC - Freq or Phase Word" , "openhpsdr-e.cr.gen.freq-phase", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&phase_freq), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_atlas_merc_cfg,
           { "Atlas Mercury DDC Conf" , "openhpsdr-e.cr.gen.atlas-merc",
            FT_UINT8, BASE_DEC,
            VALS(cr_gen_atlas_merc), MASKBITS_2_1_0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_10mhz,
           { " 10MHz Ref Source" , "openhpsdr-e.cr.gen.10mhz",
            FT_UINT8, BASE_DEC,
            VALS(cr_gen_10mhz), MASKBITS_1_0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_pa,
           { "PA (VNA mode or Tansverter Out)" , "openhpsdr-e.cr.gen.pa", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_apollo_atu_auto,
           { "    Apollo ATU Auto Tune" , "openhpsdr-e.cr.gen.apollo-atu-auto", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_merc_comm_freq,
           { "Mult Mercury Common Freq" , "openhpsdr-e.cr.gen.merc-comm-freq", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&same_independent), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_122880khz,
           { "    122.88MHz Ref Source" , "openhpsdr-e.cr.gen.apollo-atu-auto", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&mercury_penelope), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_0,
           { "           Alex 0" , "openhpsdr-e.cr.gen.alex-0", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_1,
           { "           Alex 1" , "openhpsdr-e.cr.gen.alex-1", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_2,
           { "           Alex 2" , "openhpsdr-e.cr.gen.alex-2", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_3,
           { "           Alex 3" , "openhpsdr-e.cr.gen.alex-3", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_4,
           { "           Alex 4" , "openhpsdr-e.cr.gen.alex-4", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_5,
           { "           Alex 5" , "openhpsdr-e.cr.gen.alex-5", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_6,
           { "           Alex 6" , "openhpsdr-e.cr.gen.alex-6", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_cr_gen_alex_7,
           { "           Alex 7" , "openhpsdr-e.cr.gen.alex-7", 
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },

    };

    // DDC Command Field Arrary
    static hf_register_info hf_ddcc[] = {
       { &hf_openhpsdr_e_ddcc_banner,
           { "openHPSDR Ethernet - DDC Command" , "openhpsdr-e.ddcc.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_sequence_num,
           { "Sequence Number", "openhpsdr-e.ddcc.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };
  
    // High Priority Status Field Arrary
    static hf_register_info hf_hps[] = {
       { &hf_openhpsdr_e_hps_banner,
           { "openHPSDR Ethernet - High Priority Status" , "openhpsdr-e.hps.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_sequence_num,
           { "Sequence Number", "openhpsdr-e.hps.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };  

    // DUC Command Field Arrary
    static hf_register_info hf_ducc[] = {
       { &hf_openhpsdr_e_ducc_banner,
           { "openHPSDR Ethernet - DUC Command" , "openhpsdr-e.ducc.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_sequence_num,
           { "Sequence Number", "openhpsdr-e.ducc.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };  

    // MICL Command Field Arrary
    static hf_register_info hf_micl[] = {
       { &hf_openhpsdr_e_micl_banner,
           { "openHPSDR Ethernet - MIC / Line Samples" , "openhpsdr-e.micl.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_micl_sequence_num,
           { "Sequence Number", "openhpsdr-e.micl.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };  

    // High Priority Command Field Arrary
    static hf_register_info hf_hpc[] = {
       { &hf_openhpsdr_e_hpc_banner,
           { "openHPSDR Ethernet - High Priority Command" , "openhpsdr-e.hpc.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_sequence_num,
           { "Sequence Number", "openhpsdr-e.hpc.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   }; 

    // Wide Band Data Field Arrary
    static hf_register_info hf_wbd[] = {
       { &hf_openhpsdr_e_wbd_banner,
           { "openHPSDR Ethernet - Wide Band Data" , "openhpsdr-e.wbd.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_wbd_sequence_num,
           { "Sequence Number", "openhpsdr-e.wbd.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   }; 

    // DDC Audio Field Arrary
    static hf_register_info hf_ddca[] = {
       { &hf_openhpsdr_e_ddca_banner,
           { "openHPSDR Ethernet - DDC Audio" , "openhpsdr-e.ddca.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddca_sequence_num,
           { "Sequence Number", "openhpsdr-e.ddca.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   }; 

   // DUC I&Q Data Field Arrary
    static hf_register_info hf_duciq[] = {
       { &hf_openhpsdr_e_duciq_banner,
           { "openHPSDR Ethernet - DUC I&Q Data" , "openhpsdr-e.duciq.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_duciq_sequence_num,
           { "Sequence Number", "openhpsdr-e.duciq.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   }; 

   // DDC I&Q Data Field Arrary
    static hf_register_info hf_ddciq[] = {
       { &hf_openhpsdr_e_ddciq_banner,
           { "openHPSDR Ethernet - DDC I&Q Data" , "openhpsdr-e.ddciq.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_sequence_num,
           { "Sequence Number", "openhpsdr-e.ddciq.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   }; 

    // Memory Mapped Field Arrary
    static hf_register_info hf_mem[] = {
       { &hf_openhpsdr_e_mem_banner,
           { "openHPSDR Ethernet - Memory Mapped" , "openhpsdr-e.mem.banner",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_mem_sequence_num,
           { "Sequence Number", "openhpsdr-e.mem.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };

   proto_openhpsdr_e = proto_register_protocol (
       "openHPSDR Ethernet",  // name       
       "openHPSDR",          // short name 
       "hpsdr-e"            // abbrev     
   );

   // Register the arrays
   proto_register_field_array(proto_openhpsdr_e, hf, array_length(hf));
   proto_register_field_array(proto_openhpsdr_e, hf_cr, array_length(hf_cr));
   proto_register_field_array(proto_openhpsdr_e, hf_ddcc, array_length(hf_ddcc));
   proto_register_field_array(proto_openhpsdr_e, hf_hps, array_length(hf_hps));
   proto_register_field_array(proto_openhpsdr_e, hf_ducc, array_length(hf_ducc));
   proto_register_field_array(proto_openhpsdr_e, hf_micl, array_length(hf_micl));
   proto_register_field_array(proto_openhpsdr_e, hf_hpc, array_length(hf_hpc));
   proto_register_field_array(proto_openhpsdr_e, hf_wbd, array_length(hf_wbd));
   proto_register_field_array(proto_openhpsdr_e, hf_ddca, array_length(hf_ddca));
   proto_register_field_array(proto_openhpsdr_e, hf_duciq, array_length(hf_duciq));
   proto_register_field_array(proto_openhpsdr_e, hf_ddciq, array_length(hf_ddciq));
   proto_register_field_array(proto_openhpsdr_e, hf_mem, array_length(hf_mem));

   proto_register_subtree_array(ett, array_length(ett));
   //proto_register_subtree_array(ett_cr, array_length(ett_ddcc));

   // Required function calls to register expert items
   expert_openhpsdr_e_cr = expert_register_protocol(proto_openhpsdr_e);
   expert_register_field_array(expert_openhpsdr_e_cr, ei_cr, array_length(ei_cr));

    //Register configuration preferences
   openhpsdr_e_prefs = prefs_register_protocol(proto_openhpsdr_e,NULL);



   prefs_register_bool_preference(openhpsdr_e_prefs,"strict_size",
       "Strict Checking of Datagram Size",
       "Disable checking for added bytes at the end of the datagrams."
       " Disables the warning message.",
       &openhpsdr_e_strict_size);
 
   prefs_register_bool_preference(openhpsdr_e_prefs,"strict_pad",
       "Strict Pad Checking",  
       "Strict checking of the amount of pad bytes at the end of the datagrams."
       " When enabled, Wireshark (not the openHPSDR dissector) will display"
       " a \"Malformed Packet\" error for a datagram without the correct"
       " number of pad bytes." 
       " When disabled, checking is only for one pad byte instead of checking"
       " for the correct number of pad bytes.", 
       &openhpsdr_e_strict_pad);

   prefs_register_bool_preference(openhpsdr_e_prefs,"strict_program_data_size",
       "Program Data Roll Over Checking (CR)",  
       "Program Data Roll Over is when the" 
       " Sequence Number * 256 (max program bytes per program datagram)"
       " is larger than the number of Program Blocks listed in the datagram."
       " Disables the warning message.",
       &openhpsdr_e_cr_strict_program_data_size);
     
}


gint cr_packet_end_pad(tvbuff_t *tvb, proto_tree *tree, gint offset, gint size)
{ 
   gint length = -1;

   proto_item *local_append_text_item = NULL;

   if (openhpsdr_e_strict_pad) { length = size; }
   else { length = 1; }

   local_append_text_item = proto_tree_add_item(tree,hf_openhpsdr_e_cr_pad,tvb,offset,
                         length,ENC_BIG_ENDIAN);
               
   if (openhpsdr_e_strict_pad) { proto_item_append_text(local_append_text_item," (%d Bytes)",size); }
   else { proto_item_append_text(local_append_text_item," (%d Bytes) -Disabled",size); }
   offset += size; 

   return offset;
}

guint8 cr_discovery_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
   guint8 board_id = -1;
   guint8 value = -1;
   guint8 boolean_byte = -1;

   const guint8 *discovery_ether_mac;
   discovery_ether_mac = tvb_get_ptr(tvb, 5, 6); // Has to be defined before using.

   proto_tree_add_ether(tree, hf_openhpsdr_e_cr_disc_mac, tvb,offset, 6, discovery_ether_mac);
   offset += 6;

   board_id = tvb_get_guint8(tvb, offset);
   proto_tree_add_item(tree,hf_openhpsdr_e_cr_disc_board,tvb,offset,1,ENC_BIG_ENDIAN);
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_fw_ver,tvb,offset,1,value,
       "Firmware Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc0_ver,tvb,offset,1,value,
       "Mercury0 Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc1_ver,tvb,offset,1,value,
       "Mercury1 Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc2_ver,tvb,offset,1,value,
       "Mercury2 Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc3_ver,tvb,offset,1,value,
       "Mercury3 Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_penny_ver,tvb,offset,1,value,
       "Penny   Version : %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_metis_ver,tvb,offset,1,value,
       "Metis   Version : %d.%.1d",(value/10),(value%10));
   offset += 1;

   proto_tree_add_item(tree,hf_openhpsdr_e_cr_disc_ddc_num,tvb,offset,1,ENC_BIG_ENDIAN);
   offset += 1;

   boolean_byte = tvb_get_guint8(tvb, offset);
   proto_tree_add_boolean(tree, hf_openhpsdr_e_cr_disc_freq_phase, tvb,offset, 1, boolean_byte);
   offset += 1;

   offset = cr_packet_end_pad(tvb,tree,offset,39);
   cr_check_length(tvb,pinfo,tree,offset);

   return board_id;
}

void cr_check_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
 
   guint length_remaining = -1;
   const char *placehold = NULL ;

   proto_item *ei_item = NULL;

   if ( !(openhpsdr_e_strict_size) ) { return; }

   if ( tvb_captured_length(tvb) > (guint)offset) {
       length_remaining = tvb_ensure_captured_length_remaining(tvb, offset); 
       ei_item = proto_tree_add_string_format(tree, hf_openhpsdr_e_cr_ei, tvb, 
                     offset, length_remaining, placehold,"Extra Length");
       expert_add_info_format(pinfo,ei_item,&ei_cr_extra_length,
           "Extra Bytes in packet, %d extra bytes.",length_remaining);
   }
                 
}

// Port 1024  Command Reply (cr)  - My name for protocol
//
// Host to Hardware
// To Port    Command         Name
// 1024       0x00            General Packet
// 1024       0x02            Discovery Packet
// 1024       0x03            Set IP Address Packet
// 1024       0x04            Erase Packet
// 1024       0x05            Program Packet

// Hardware to Host
// From Port     Command     Name
// 1024          0x02        Discovery Reply Packet
// 1024          0x03        Discovery Reply Packet (In Use) ????
// 1024          0x03        Erase Ack / Erase Complete
// 1024          0x04        Program Data Request
static void dissect_openhpsdr_e_cr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;
   gint error = -1;
   gint data_length = -1;

   guint cr_command = -1;

   guint8 boolean_byte = -1;

   guint32 prog_seq = -1;
   guint32 prog_blocks = -1;

   //conversation_t   *conversation = NULL;

   const char *placehold = NULL ;

   const guint8 *discovery_ether_mac;
   discovery_ether_mac = tvb_get_ptr(tvb, 5, 6); // Has to be defined before using.

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR CR");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_cr_item = NULL;

       proto_tree *openhpsdr_e_cr_tree = NULL;

       proto_item *append_text_item = NULL;
       proto_item *ei_item = NULL;


       parent_tree_cr_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_cr_tree = proto_item_add_subtree(parent_tree_cr_item, ett_openhpsdr_e_cr);

       proto_tree_add_string_format(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - Command Reply");

       proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       cr_command = tvb_get_guint8(tvb, offset);
       append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_command, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       if (cr_command == 0x00) {
           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {

               proto_item_append_text(append_text_item," :General - Host to Hardware");

               openhpsdr_e_cr_ddcc_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item= proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_ddcc_port,
                                     tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Dest Port");
               offset += 2;

               openhpsdr_e_cr_ducc_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_ducc_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Dest Port");
               offset += 2;

               openhpsdr_e_cr_hpc_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_hpc_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item," -Dest Port");
               offset += 2;

               openhpsdr_e_cr_hps_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_hps_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Source Port");
               offset += 2;

               openhpsdr_e_cr_ddca_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_ddca_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Dest Port");
               offset += 2;

               openhpsdr_e_cr_duciq_base_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_duciq_base_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Dest Port");
               offset += 2;

               openhpsdr_e_cr_ddciq_base_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_ddciq_base_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item," -Source Port"); 
               offset += 2;

               openhpsdr_e_cr_micl_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_micl_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Source Port"); 
               offset += 2;

               openhpsdr_e_cr_wbd_base_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wbd_base_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Source Port"); 
               offset += 2;

               boolean_byte = tvb_get_guint8(tvb, offset);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_0, tvb,offset, 1, boolean_byte);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_1, tvb,offset, 1, boolean_byte);               
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_2, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_3, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_4, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_5, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_6, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_7, tvb,offset, 1, boolean_byte);  
               offset += 1;

               proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_gen_wb_samples,tvb,offset,2, ENC_BIG_ENDIAN);
               offset += 2; 

               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_gen_wb_size,
                                      tvb,offset,1,ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item," Bits");

               offset += 1;

               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_gen_wb_rate,
                                      tvb,offset,1, ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item,"mS");
               offset += 1;

               proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_gen_wb_datagrams_full_spec,tvb,offset,1, ENC_BIG_ENDIAN);
               offset += 1;

               openhpsdr_e_cr_mem_host_port  = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_mem_host_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Dest Port"); 
               offset += 2;

               openhpsdr_e_cr_mem_hw_port = tvb_get_guint16(tvb, offset,2);     
               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_mem_hw_port, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN); 
               proto_item_append_text(append_text_item," -Source Port"); 
               offset += 2;

               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_pwm_env_min, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item," Reserved for Future Use");
               offset += 2;

               append_text_item = proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_pwm_env_min, 
                                      tvb,offset, 2, ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item," Reserved for Future Use");
               offset += 2;

               boolean_byte = tvb_get_guint8(tvb, offset);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_iq_ts, tvb,offset, 1, boolean_byte);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_vita, tvb,offset, 1, boolean_byte);               
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_vna, tvb,offset, 1, boolean_byte);  
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_freq_phase, tvb,offset, 1, boolean_byte);   
               offset += 1;

               proto_tree_add_string_format(openhpsdr_e_cr_tree,hf_openhpsdr_e_reserved ,tvb,offset,18,placehold,
                   "                             : Reserved for Future Use");
               offset += 18;
 
               proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_gen_atlas_merc_cfg,tvb,offset,1,
                   ENC_BIG_ENDIAN);             
               offset += 1; 

               proto_tree_add_item(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_10mhz, tvb,offset, 1, boolean_byte);
               offset += 1;

               boolean_byte = tvb_get_guint8(tvb, offset);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_pa, tvb,offset, 1, boolean_byte);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_apollo_atu_auto, tvb,offset, 1,
                   boolean_byte);               
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_merc_comm_freq, tvb,offset, 1,
                   boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_122880khz, tvb,offset, 1, boolean_byte);
               offset += 1;

               boolean_byte = tvb_get_guint8(tvb, offset);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_0, tvb,offset, 1, boolean_byte);
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_1, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_2, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_3, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_4, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_5, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_6, tvb,offset, 1, boolean_byte); 
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_alex_7, tvb,offset, 1, boolean_byte); 
               offset += 1;  

               cr_check_length(tvb,pinfo,tree,offset);             

           }

       } else if (cr_command == 0x02) { // Discovery

           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {
               
               proto_item_append_text(append_text_item," :Discovery - Host Discovery Query");

               offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,55);
               cr_check_length(tvb,pinfo,openhpsdr_e_cr_tree,offset);
               
           } else if (pinfo->srcport == HPSDR_E_PORT_COM_REP) {
            
               proto_item_append_text(append_text_item," :Discovery - Hardware Discovery Reply");
               cr_discovery_reply(tvb,pinfo,openhpsdr_e_cr_tree,offset);

           }


       } else if (cr_command == 0x03) { // 0x03 Set IP Address - Discovery Reply (in use) - Erase Reply

           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {
               proto_item_append_text(append_text_item," :Set IP Address - Host Set IP Address");

               proto_tree_add_ether(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_setip_mac, tvb,offset, 6, discovery_ether_mac);
               offset += 6;
               proto_tree_add_ipv4(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_setip_ip, tvb,offset, 4,tvb_get_ipv4(tvb,offset));
               offset += 4; 

               offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,45);
               cr_check_length(tvb,pinfo,openhpsdr_e_cr_tree,offset); 

           } else if (pinfo->srcport == HPSDR_E_PORT_COM_REP) {
               proto_item_append_text(append_text_item," :Discovery - Hardware Discovery Reply (Hardware In Use)");
               cr_discovery_reply(tvb,pinfo,openhpsdr_e_cr_tree,offset);

// Hardware Erase reply needs to be added here !!!!!!!!!!!!

           } 

       } else if (cr_command == 0x04) { // 0x04 Erase - Program Data Request
           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {
               proto_item_append_text(append_text_item," :Erase - Host Erase Command");

               offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,55);
               cr_check_length(tvb,pinfo,openhpsdr_e_cr_tree,offset);

           } else if (pinfo->srcport == HPSDR_E_PORT_COM_REP) {
               proto_item_append_text(append_text_item," :Program - Hardware Program Data Request (Reply)");
               cr_discovery_reply(tvb,pinfo,openhpsdr_e_cr_tree,offset);

           }

       } else if (cr_command == 0x05) { // 0x05 Program

           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {

               proto_item_append_text(append_text_item," :Program - Host Program Data");
               prog_seq = tvb_get_guint32(tvb, offset-5,4);
               prog_blocks = tvb_get_guint32(tvb, offset,4);
 
               // Assumes that the sequence number can be used as a
               // indicator of the number programing blocks sent.
               if ( (prog_blocks / (prog_seq * 256)) == 0 ) {
                   data_length = (prog_seq * 256) - prog_blocks;
                   if ( data_length > 256 ) {  // Roll over
                       data_length = 256; 
                       error = 1; 
                   }
               } else {
                   data_length = 256;
               }
       
               proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_prog_blocks,tvb,offset,4,ENC_BIG_ENDIAN);   
               offset += 4;

               append_text_item =  proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_prog_data,tvb,offset,
                                       data_length,ENC_BIG_ENDIAN);
               proto_item_append_text(append_text_item,": Programing Data (%d Bytes)",data_length);
               offset += data_length; 
                
               if ( data_length < 256) {
                   offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,(256-data_length));
               }

               if ( error == 1 && openhpsdr_e_cr_strict_program_data_size ) {
                   ei_item = proto_tree_add_string_format(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_ei, tvb, 
                                 offset, ((prog_seq * 256) - prog_blocks), placehold,"Program Check Roll Over");
                   expert_add_info_format(pinfo,ei_item,&ei_cr_program_check_roll_over,
                       "Roll Over Ammount: %d",((prog_seq * 256) - prog_blocks));          
                   error = 0;
               }

               cr_check_length(tvb,pinfo,openhpsdr_e_cr_tree,offset);
           }        
 
       } 

  
   }

}

static gboolean
dissect_openhpsdr_e_cr_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is hard defined to use UDP destination or source port of 1024.

   // Heuristics test
   // - Used packet-smb.c for an example.
   // Since the older HPSDR USB over IP uses the same UDP port. 
   // Test the first two bytes for the USB over IP id.
   if ( tvb_get_guint16(tvb, 0,2) == 0xEFFE ) {
       return FALSE;
   }

   // Make sure it's port 1024 traffic
   if ( (pinfo->srcport == HPSDR_E_PORT_COM_REP) || (pinfo->destport == HPSDR_E_PORT_COM_REP) ) {

       dissect_openhpsdr_e_cr(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }


}

// Host to Hardware
// To Port    Name
// 1025       DDC Command
static void dissect_openhpsdr_e_ddcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;   

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DDCC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ddcc_item = NULL;

       proto_tree *openhpsdr_e_ddcc_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ddcc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ddcc_tree = proto_item_add_subtree(parent_tree_ddcc_item, ett_openhpsdr_e_ddcc);

       proto_tree_add_string_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DDC Command");       

       proto_tree_add_item(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_ddcc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is defined by its DESTINATION port.
   // The port is defined by bytes 5 and 6 of host sent Command Reply (0x00) datagram.
   // The default port is 1025. A 0 in bytes 5 and 6 means use the default port.  
   if ( pinfo->destport == HPSDR_E_PORT_DDC_COM ) {

       dissect_openhpsdr_e_ddcc(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->destport == openhpsdr_e_cr_ddcc_port ) { // Non-default port  

       dissect_openhpsdr_e_ddcc(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Hardware to Host 
// From Port    Name
// 1025         High Priority Status 
static void dissect_openhpsdr_e_hps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR HPS");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_hps_item = NULL;

       proto_tree *openhpsdr_e_hps_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_hps_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_hps_tree = proto_item_add_subtree(parent_tree_hps_item, ett_openhpsdr_e_hps);

       proto_tree_add_string_format(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - High Priority Status");

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_hps_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

   // The protocol is defined by its SOURCE port.
   // The port is defined by bytes 11 and 12 of host sent Command Reply (0x00) datagram.
   // The default port is 1025. A 0 in bytes 11 and 12 means use the default port.     
   if ( pinfo->srcport == HPSDR_E_PORT_HP_STAT ) {

       dissect_openhpsdr_e_hps(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->srcport == openhpsdr_e_cr_hps_port ) { // Non-default port  

       dissect_openhpsdr_e_hps(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Host to Hardware
// To Port    Name
// 1026       DUC Command
static void dissect_openhpsdr_e_ducc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DUCC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ducc_item = NULL;

       proto_tree *openhpsdr_e_ducc_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ducc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ducc_tree = proto_item_add_subtree(parent_tree_ducc_item, ett_openhpsdr_e_ducc);

       proto_tree_add_string_format(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DUC Command");

       proto_tree_add_item(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_ducc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is defined by its DESTINATION port.
   // The port is defined by bytes 7 and 8 of host sent Command Reply (0x00) datagram.
   // The default port is 1026. A 0 in bytes 7 and 8 means use the default port.      
   if ( pinfo->destport == HPSDR_E_PORT_DUC_COM ) {

       dissect_openhpsdr_e_ducc(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->destport == openhpsdr_e_cr_ducc_port ) { // Non-default port  

       dissect_openhpsdr_e_ducc(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Hardware to Host
// From Port    Name
// 1026       Mic / Line Samples 
static void dissect_openhpsdr_e_micl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR MICL");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_micl_item = NULL;

       proto_tree *openhpsdr_e_micl_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_micl_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_micl_tree = proto_item_add_subtree(parent_tree_micl_item, ett_openhpsdr_e_micl);

       proto_tree_add_string_format(openhpsdr_e_micl_tree, hf_openhpsdr_e_micl_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - Mic / Line Samples");

       proto_tree_add_item(openhpsdr_e_micl_tree, hf_openhpsdr_e_micl_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_micl_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is defined by its SOURCE port.
   // The port is defined by bytes 19 and 20 of host sent Command Reply (0x00) datagram.
   // The default port is 1027. A 0 in bytes 19 and 20 means use the default port.    
   if ( pinfo->srcport == HPSDR_E_PORT_MICL_S ) {

       dissect_openhpsdr_e_micl(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->srcport == openhpsdr_e_cr_micl_port ) { // Non-default port  

       dissect_openhpsdr_e_micl(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Host to Hardware
// To Port    Name
// 1027       High Priority Command 
static void dissect_openhpsdr_e_hpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR HPC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_hpc_item = NULL;

       proto_tree *openhpsdr_e_hpc_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_hpc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_hpc_tree = proto_item_add_subtree(parent_tree_hpc_item, ett_openhpsdr_e_hpc);

       proto_tree_add_string_format(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - High Priority Command");

       proto_tree_add_item(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_hpc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is defined by its DESTINATION port.
   // The port is defined by bytes 9 and 10 of host sent Command Reply (0x00) datagram.
   // The default port is 1027. A 0 in bytes 9 and 10 means use the default port.    
   if ( pinfo->destport == HPSDR_E_PORT_HP_COM ) {

       dissect_openhpsdr_e_hpc(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->destport == openhpsdr_e_cr_hpc_port ) { // Non-default port  

       dissect_openhpsdr_e_hpc(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Hardware to Host
// From Port    Name
// 1027       Wide Band Data Base Port
// 1027       WB0 (ADC0) 
// 1028       WB1 (ADC1) 
// 1029       WB2 (ADC2) 
// 1030       WB3 (ADC3) 
// 1031       WB4 (ADC4) 
// 1032       WB5 (ADC5) 
// 1033       WB6 (ADC6) 
// 1034       WB7 (ADC7) 
static void dissect_openhpsdr_e_wbd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR WBD");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_wbd_item = NULL;

       proto_tree *openhpsdr_e_wbd_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_wbd_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_wbd_tree = proto_item_add_subtree(parent_tree_wbd_item, ett_openhpsdr_e_wbd);

       proto_tree_add_string_format(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - Wide Band Data");

       proto_tree_add_item(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_wbd_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // Page 2 vers 2.6 of protocol specification document: 
   // "For the current hardware implementation an arbitrary limit of 80 DDCs and 8 ADCs has been 
   // applied. These limits will be removed as hardware that is capable of exceeding these settings 
   // becomes available." 
   //
   // So there are 8 ADCs which means 8 UDP ports for Wide Band Data.

   // The protocol is defined by its SOURCE port.
   // The port is defined by bytes 21 and 22 of host sent Command Reply (0x00) datagram.
   // The default port is 1027. A 0 in bytes 21 and 22 means use the default port.    
   if ( pinfo->srcport >= HPSDR_E_BPORT_WB_DAT && pinfo->srcport <= (guint16)(HPSDR_E_BPORT_WB_DAT + 7) ) {

       dissect_openhpsdr_e_wbd(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->srcport >= openhpsdr_e_cr_wbd_base_port &&
               pinfo->srcport <= (guint16)(openhpsdr_e_cr_wbd_base_port + 7) ) {  // Non-default port

       dissect_openhpsdr_e_wbd(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Host to Hardware
// To Port    Name
// 1028       DDC Audio
static void dissect_openhpsdr_e_ddca(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DDCA");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ddca_item = NULL;

       proto_tree *openhpsdr_e_ddca_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ddca_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ddca_tree = proto_item_add_subtree(parent_tree_ddca_item, ett_openhpsdr_e_ddca);

       proto_tree_add_string_format(openhpsdr_e_ddca_tree, hf_openhpsdr_e_ddca_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DDC Audio");

       proto_tree_add_item(openhpsdr_e_ddca_tree, hf_openhpsdr_e_ddca_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_ddca_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // The protocol is defined by its DESTINATION port.
   // The port is defined by bytes 13 and 14 of host sent Command Reply (0x00) datagram.
   // The default port is 1028. A 0 in bytes 13 and 14 means use the default port.  
   if ( pinfo->destport == HPSDR_E_PORT_DDC_AUD ) {

       dissect_openhpsdr_e_ddca(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->destport == openhpsdr_e_cr_ddca_port ) { // Non-default port  

       dissect_openhpsdr_e_ddca(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Host to Hardware
// To Port    Name
// 1029       DUC I&Q Data (Base Port)
// 1029	      DUC0
// 1030       DUC1
// 1031       DUC2
// 1032       DUC3
// 1033       DUC4
// 1034       DUC5
// 1035       DUC6
// 1036       DUC7
static void dissect_openhpsdr_e_duciq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DUCIQ");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_duciq_item = NULL;

       proto_tree *openhpsdr_e_duciq_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_duciq_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_duciq_tree = proto_item_add_subtree(parent_tree_duciq_item, ett_openhpsdr_e_duciq);

       proto_tree_add_string_format(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DUC I&Q Data");

       proto_tree_add_item(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_duciq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // Page 2 vers 2.6 of protocol specification document: 
   // "For the current hardware implementation an arbitrary limit of 80 DDCs and 8 ADCs has been 
   // applied. These limits will be removed as hardware that is capable of exceeding these settings 
   // becomes available."
   //
   // So there are 8 ADCs which means 8 UDP ports for Digital Up Converters (DUC).
    

   // The protocol is defined by its DESTINATION port.
   // The port is defined by bytes 15 and 16 of host sent Command Reply (0x00) datagram.
   // The default base port is 1028. A 0 in bytes 15 and 16 means use the default port.  
   if ( pinfo->destport >= HPSDR_E_BPORT_DUC_IQ && pinfo->destport <= (guint16)(HPSDR_E_BPORT_DUC_IQ + 7)  ) {

       dissect_openhpsdr_e_duciq(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->destport >= openhpsdr_e_cr_duciq_base_port && 
               pinfo->destport <= (guint16)(openhpsdr_e_cr_duciq_base_port + 7) ) { // Non-default port  

       dissect_openhpsdr_e_duciq(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Hardware to Host
// From Port    Name
// 1035       DDC I&Q Data (Base Port)
// 1035       DDC0 
// ...        ...
// 1114       DDC79 
static void dissect_openhpsdr_e_ddciq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DDCIQ");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ddciq_item = NULL;

       proto_tree *openhpsdr_e_ddciq_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ddciq_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ddciq_tree = proto_item_add_subtree(parent_tree_ddciq_item, ett_openhpsdr_e_ddciq);

       proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DDC I&Q Data");

       proto_tree_add_item(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_ddciq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
   // Page 2 vers 2.6 of protocol specification document: 
   // "For the current hardware implementation an arbitrary limit of 80 DDCs and 8 ADCs has been 
   // applied. These limits will be removed as hardware that is capable of exceeding these settings 
   // becomes available."
   //
   // So there are 80 Digital Up Converters (DDC) which means 80 UDP ports for DDCs.
    

   // The protocol is defined by its SOURCE port.
   // The port is defined by bytes 17 and 18 of host sent Command Reply (0x00) datagram.
   // The default base port is 1035. A 0 in bytes 17 and 18 means use the default port.  
   if ( pinfo->srcport >= HPSDR_E_BPORT_DDC_IQ && pinfo->srcport <= (guint16)(HPSDR_E_BPORT_DDC_IQ + 79)  ) {

       dissect_openhpsdr_e_ddciq(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->srcport >= openhpsdr_e_cr_ddciq_base_port && 
               pinfo->srcport <= (guint16)(openhpsdr_e_cr_ddciq_base_port + 79) ) { // Non-default port  

       dissect_openhpsdr_e_ddciq(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

// Memory Mapped
// Port    Name
// xxxx    Memory Mapped
// - No default port
// - Host and Hardward use the same protocol. 
static void dissect_openhpsdr_e_mem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR MEM");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_mem_item = NULL;

       proto_tree *openhpsdr_e_mem_tree = NULL;

       //proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_mem_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_mem_tree = proto_item_add_subtree(parent_tree_mem_item, ett_openhpsdr_e_mem);

       proto_tree_add_string_format(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - Memory Mapped");

       proto_tree_add_item(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

   }

}

static gboolean
dissect_openhpsdr_e_mem_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{


   // The protocol is defined by its port. 
   // There are two different ports. One for the Host and one for the Hardware.
   // There is no default port.
   // The Host port is defined by bytes 29 and 30 of host sent Command Reply (0x00) datagram.
   // Assuming the Host port is a destination port like the other potocols.
   // The next available port for destination ports from Host is 1037,Doc vers 2.6.  
   // The Hardware port is defined by bytes 31 and 32 of host sent Command Reply (0x00) datagram.
   // Assuming the Hardware port is a source port like the other potocols. 
   // The next available port for destination ports from Host is 1115,Doc vers 2.6. 
   //
   // Ports below 1024 are not allowed. They are not user ports. See ITEF RFC 6335.
   if ( pinfo->destport == openhpsdr_e_cr_mem_host_port && pinfo->destport >= 1037 ) {
       // Host Port   
       dissect_openhpsdr_e_mem(tvb, pinfo, tree);
       return TRUE;

   } else if ( pinfo->srcport == openhpsdr_e_cr_mem_hw_port && pinfo->srcport >= 1115 ) {
       // Hardware Port   
       dissect_openhpsdr_e_mem(tvb, pinfo, tree);
       return TRUE;

   } else {
       return FALSE;
   }

}

void
proto_reg_handoff_openhpsdr_e(void)
{
   
   static gboolean cr_initialized = FALSE;
   static gboolean ddcc_initialized = FALSE;
   static gboolean hps_initialized = FALSE;
   static gboolean ducc_initialized = FALSE;
   static gboolean micl_initialized = FALSE;
   static gboolean hpc_initialized = FALSE;
   static gboolean wbd_initialized = FALSE;
   static gboolean ddca_initialized = FALSE;
   static gboolean duciq_initialized = FALSE;
   static gboolean ddciq_initialized = FALSE;
   static gboolean mem_initialized = FALSE;

   //static dissector_handle_t openhpsdr_e_handle;

   // Heuristic dissectors

   // Command Reply (cr)
   // Can not register as a normal dissector on port 1024.
   // The HPSDR USB is on port 1024 too. 
   // register as heuristic dissector
   if (!cr_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_cr_heur, 
                          "openHSPDR Ethernet - Command(Host), Reply(Hardware)",
                          "openhpsdr-e.cr", proto_openhpsdr_e, HEURISTIC_ENABLE);
       cr_initialized = TRUE; 
   }

   // There are two protocols on port 1025.
   // One from the Host and a different format coming
   // from Hardware.
   // Also the protocol specification allow for any port.
   if (!ddcc_initialized ) { 
       heur_dissector_add("udp", dissect_openhpsdr_e_ddcc_heur,
                          "openHSPDR Ethernet - DDC Command (From Host)",  
                          "openhpsdr-e.ddc", proto_openhpsdr_e, HEURISTIC_ENABLE);
       ddcc_initialized = TRUE; 
   }

   if (!hps_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_hps_heur,
                          "openHSPDR Ethernet - High Priority Status (From Hardware)",  
                          "openhpsdr-e.hps", proto_openhpsdr_e, HEURISTIC_ENABLE);
       hps_initialized = TRUE; 
   }

   // There are two protocols on port 1026.
   // One from the Host and a different format coming
   // from Hardware.
   // Also the protocol specification allow for any port. 
   if (!ducc_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_ducc_heur,
                          "openHSPDR Ethernet - DUC Command (From Host)",  
                          "openhpsdr-e.ducc", proto_openhpsdr_e, HEURISTIC_ENABLE);
       ducc_initialized = TRUE; 
   }

   if (!micl_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_micl_heur,
                          "openHSPDR Ethernet - Mic / Line Samples (From Hardware)",  
                          "openhpsdr-e.micl", proto_openhpsdr_e, HEURISTIC_ENABLE);
       micl_initialized = TRUE; 
   }

   // Port 1027
   // One from the Host and a different format coming
   // from Hardware.
   // Also the protocol specification allow for any port.
   if (!hpc_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_hpc_heur,
                          "openHSPDR Ethernet - High Priority Command (From Host)",  
                          "openhpsdr-e.hpc", proto_openhpsdr_e, HEURISTIC_ENABLE);
       hpc_initialized = TRUE; 
   }

   // Base Port of 1027 
   // Sourced from hardware.
   // Ports 1027 to 1034 at time of protocol doc vers 2.6.
   // The potocol specification allow for any port.

   if (!wbd_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_wbd_heur,
                          "openHSPDR Ethernet - Wide Band Data (From Hardware)",  
                          "openhpsdr-e.wbd", proto_openhpsdr_e, HEURISTIC_ENABLE);
       wbd_initialized = TRUE; 
   }


   // Port 1028
   // The potocol specification allow for any port.
   if (!ddca_initialized ) { 
       heur_dissector_add("udp", dissect_openhpsdr_e_ddca_heur,
                          "openHSPDR Ethernet - DDC Audio (From Host)",  
                          "openhpsdr-e.ddca", proto_openhpsdr_e, HEURISTIC_ENABLE);
       ddca_initialized = TRUE; 
   }

   // Base Port 1029
   // Ports 1029 to 1036 at time of protocol doc vers 2.6.
   // The potocol specification allow for any port.
   if (!duciq_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_duciq_heur,
                          "openHSPDR Ethernet - DUC I&Q Data (From Host)",  
                          "openhpsdr-e.duciq", proto_openhpsdr_e, HEURISTIC_ENABLE);
       duciq_initialized = TRUE; 
   }

   // Base Port 1035
   // Ports 1035 to 1114 at time of protocol doc vers 2.6.
   // The potocol specification allow for any port.
   if (!ddciq_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_ddciq_heur,
                          "openHSPDR Ethernet - DDC I&Q Data (From Hardware)",  
                          "openhpsdr-e.ddciq", proto_openhpsdr_e, HEURISTIC_ENABLE);
       ddciq_initialized = TRUE; 
   }


   // Memory Mapped - No default port
   // The Host and Hardware may using different ports.
   // Assuming the Host port is a destination port like the other potocols.
   // Assuming the Hardware port is a source port like the other potocols.
   // The protocol specification allow for any port.
   if (!mem_initialized ) {
       heur_dissector_add("udp", dissect_openhpsdr_e_mem_heur,
                          "openHSPDR Ethernet - Memory Mapped",  
                          "openhpsdr-e.mem", proto_openhpsdr_e, HEURISTIC_ENABLE);
       mem_initialized = TRUE; 
   }


   // Register as a normal dissectors
   
   //DDC Command (ddcc)
   //openhpsdr_e_handle = create_dissector_handle(dissect_openhpsdr_e_ddcc,proto_openhpsdr_e);
   //dissector_add_uint("udp.port", HPSDR_E_PORT_DDC_COM,openhpsdr_e_handle);
   //dissector_add_string

}

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
// ducc  - DUC Command (Host to Hardware - dest port 1026)
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


#include <stdlib.h>
//#include <string.h>
//#include <math.h>
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
static gint ett_openhpsdr_e_ddcc_ditram = -1;
static gint ett_openhpsdr_e_ddcc_state = -1;
static gint ett_openhpsdr_e_ddcc_config = -1;
static gint ett_openhpsdr_e_ddcc_sync = -1;
static gint ett_openhpsdr_e_ddcc_mux = -1;
static gint ett_openhpsdr_e_hps = -1;
static gint ett_openhpsdr_e_ducc = -1;
static gint ett_openhpsdr_e_micl = -1;
static gint ett_openhpsdr_e_hpc = -1;
static gint ett_openhpsdr_e_hpc_ddc_fp = -1;
static gint ett_openhpsdr_e_hpc_alex0 = -1;
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
static int hf_openhpsdr_e_ddcc_adc_num = -1;
static int hf_openhpsdr_e_ddcc_ditram_sub = -1;
static int hf_openhpsdr_e_ddcc_adc_dither0 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither1 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither2 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither3 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither4 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither5 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither6 = -1;
static int hf_openhpsdr_e_ddcc_adc_dither7 = -1;
static int hf_openhpsdr_e_ddcc_adc_random0 = -1;
static int hf_openhpsdr_e_ddcc_adc_random1 = -1;
static int hf_openhpsdr_e_ddcc_adc_random2 = -1;
static int hf_openhpsdr_e_ddcc_adc_random3 = -1;
static int hf_openhpsdr_e_ddcc_adc_random4 = -1;
static int hf_openhpsdr_e_ddcc_adc_random5 = -1;
static int hf_openhpsdr_e_ddcc_adc_random6 = -1;
static int hf_openhpsdr_e_ddcc_adc_random7 = -1;
static int hf_openhpsdr_e_ddcc_state_sub = -1;
static int hf_openhpsdr_e_ddcc_ddc0 = -1;
static int hf_openhpsdr_e_ddcc_ddc1 = -1;
static int hf_openhpsdr_e_ddcc_ddc2 = -1;
static int hf_openhpsdr_e_ddcc_ddc3 = -1;
static int hf_openhpsdr_e_ddcc_ddc4 = -1;
static int hf_openhpsdr_e_ddcc_ddc5 = -1;
static int hf_openhpsdr_e_ddcc_ddc6 = -1;
static int hf_openhpsdr_e_ddcc_ddc7 = -1;
static int hf_openhpsdr_e_ddcc_ddc8 = -1;
static int hf_openhpsdr_e_ddcc_ddc9 = -1;
static int hf_openhpsdr_e_ddcc_ddc10 = -1;
static int hf_openhpsdr_e_ddcc_ddc11 = -1;
static int hf_openhpsdr_e_ddcc_ddc12 = -1;
static int hf_openhpsdr_e_ddcc_ddc13 = -1;
static int hf_openhpsdr_e_ddcc_ddc14 = -1;
static int hf_openhpsdr_e_ddcc_ddc15 = -1;
static int hf_openhpsdr_e_ddcc_ddc16 = -1;
static int hf_openhpsdr_e_ddcc_ddc17 = -1;
static int hf_openhpsdr_e_ddcc_ddc18 = -1;
static int hf_openhpsdr_e_ddcc_ddc19 = -1;
static int hf_openhpsdr_e_ddcc_ddc20 = -1;
static int hf_openhpsdr_e_ddcc_ddc21 = -1;
static int hf_openhpsdr_e_ddcc_ddc22 = -1;
static int hf_openhpsdr_e_ddcc_ddc23 = -1;
static int hf_openhpsdr_e_ddcc_ddc24 = -1;
static int hf_openhpsdr_e_ddcc_ddc25 = -1;
static int hf_openhpsdr_e_ddcc_ddc26 = -1;
static int hf_openhpsdr_e_ddcc_ddc27 = -1;
static int hf_openhpsdr_e_ddcc_ddc28 = -1;
static int hf_openhpsdr_e_ddcc_ddc29 = -1;
static int hf_openhpsdr_e_ddcc_ddc30 = -1;
static int hf_openhpsdr_e_ddcc_ddc31 = -1;
static int hf_openhpsdr_e_ddcc_ddc32 = -1;
static int hf_openhpsdr_e_ddcc_ddc33 = -1;
static int hf_openhpsdr_e_ddcc_ddc34 = -1;
static int hf_openhpsdr_e_ddcc_ddc35 = -1;
static int hf_openhpsdr_e_ddcc_ddc36 = -1;
static int hf_openhpsdr_e_ddcc_ddc37 = -1;
static int hf_openhpsdr_e_ddcc_ddc38 = -1;
static int hf_openhpsdr_e_ddcc_ddc39 = -1;
static int hf_openhpsdr_e_ddcc_ddc40 = -1;
static int hf_openhpsdr_e_ddcc_ddc41 = -1;
static int hf_openhpsdr_e_ddcc_ddc42 = -1;
static int hf_openhpsdr_e_ddcc_ddc43 = -1;
static int hf_openhpsdr_e_ddcc_ddc44 = -1;
static int hf_openhpsdr_e_ddcc_ddc45 = -1;
static int hf_openhpsdr_e_ddcc_ddc46 = -1;
static int hf_openhpsdr_e_ddcc_ddc47 = -1;
static int hf_openhpsdr_e_ddcc_ddc48 = -1;
static int hf_openhpsdr_e_ddcc_ddc49 = -1;
static int hf_openhpsdr_e_ddcc_ddc50 = -1;
static int hf_openhpsdr_e_ddcc_ddc51 = -1;
static int hf_openhpsdr_e_ddcc_ddc52 = -1;
static int hf_openhpsdr_e_ddcc_ddc53 = -1;
static int hf_openhpsdr_e_ddcc_ddc54 = -1;
static int hf_openhpsdr_e_ddcc_ddc55 = -1;
static int hf_openhpsdr_e_ddcc_ddc56 = -1;
static int hf_openhpsdr_e_ddcc_ddc57 = -1;
static int hf_openhpsdr_e_ddcc_ddc58 = -1;
static int hf_openhpsdr_e_ddcc_ddc59 = -1;
static int hf_openhpsdr_e_ddcc_ddc60 = -1;
static int hf_openhpsdr_e_ddcc_ddc61 = -1;
static int hf_openhpsdr_e_ddcc_ddc62 = -1;
static int hf_openhpsdr_e_ddcc_ddc63 = -1;
static int hf_openhpsdr_e_ddcc_ddc64 = -1;
static int hf_openhpsdr_e_ddcc_ddc65 = -1;
static int hf_openhpsdr_e_ddcc_ddc66 = -1;
static int hf_openhpsdr_e_ddcc_ddc67 = -1;
static int hf_openhpsdr_e_ddcc_ddc68 = -1;
static int hf_openhpsdr_e_ddcc_ddc69 = -1;
static int hf_openhpsdr_e_ddcc_ddc70 = -1;
static int hf_openhpsdr_e_ddcc_ddc71 = -1;
static int hf_openhpsdr_e_ddcc_ddc72 = -1;
static int hf_openhpsdr_e_ddcc_ddc73 = -1;
static int hf_openhpsdr_e_ddcc_ddc74 = -1;
static int hf_openhpsdr_e_ddcc_ddc75 = -1;
static int hf_openhpsdr_e_ddcc_ddc76 = -1;
static int hf_openhpsdr_e_ddcc_ddc77 = -1;
static int hf_openhpsdr_e_ddcc_ddc78 = -1;
static int hf_openhpsdr_e_ddcc_ddc79 = -1;
static int hf_openhpsdr_e_ddcc_config_sub = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_asign79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_rate79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic1_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_cic2_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_size79 = -1;
static int hf_openhpsdr_e_ddcc_sync_sub = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync0_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync1_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync2_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync3_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync4_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync5_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync6_79 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_7 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_8 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_9 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_10 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_11 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_12 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_13 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_14 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_15 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_16 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_17 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_18 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_19 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_20 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_21 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_22 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_23 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_24 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_25 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_26 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_27 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_28 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_29 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_30 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_31 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_32 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_33 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_34 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_35 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_36 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_37 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_38 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_39 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_40 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_41 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_42 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_43 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_44 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_45 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_46 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_47 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_48 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_49 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_50 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_51 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_52 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_53 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_54 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_55 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_56 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_57 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_58 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_59 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_60 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_61 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_62 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_63 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_64 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_65 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_66 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_67 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_68 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_69 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_70 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_71 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_72 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_73 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_74 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_75 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_76 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_77 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_78 = -1;
static int hf_openhpsdr_e_ddcc_ddc_sync7_79 = -1;
static int hf_openhpsdr_e_ddcc_mux_sub = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux0 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux1 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux2 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux3 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux4 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux5 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux6 = -1;
static int hf_openhpsdr_e_ddcc_ddc_mux7 = -1;

static int hf_openhpsdr_e_hps_banner = -1;
static int hf_openhpsdr_e_hps_sequence_num = -1;
static int hf_openhpsdr_e_hps_ptt = -1;
static int hf_openhpsdr_e_hps_dot = -1;
static int hf_openhpsdr_e_hps_dash = -1;
static int hf_openhpsdr_e_hps_empty = -1;
static int hf_openhpsdr_e_hps_pll = -1;
static int hf_openhpsdr_e_hps_fifo_empty = -1;
static int hf_openhpsdr_e_hps_fifo_full = -1;
static int hf_openhpsdr_e_hps_adc0_ol = -1;
static int hf_openhpsdr_e_hps_adc1_ol = -1;
static int hf_openhpsdr_e_hps_adc2_ol = -1;
static int hf_openhpsdr_e_hps_adc3_ol = -1;
static int hf_openhpsdr_e_hps_adc4_ol = -1;
static int hf_openhpsdr_e_hps_adc5_ol = -1;
static int hf_openhpsdr_e_hps_adc6_ol = -1;
static int hf_openhpsdr_e_hps_adc7_ol = -1;
static int hf_openhpsdr_e_hps_ex_power0 = -1;
static int hf_openhpsdr_e_hps_ex_power1 = -1;
static int hf_openhpsdr_e_hps_ex_power2 = -1;
static int hf_openhpsdr_e_hps_ex_power3 = -1;
static int hf_openhpsdr_e_hps_fp_alex0 = -1;
static int hf_openhpsdr_e_hps_fp_alex1 = -1;
static int hf_openhpsdr_e_hps_fp_alex2 = -1;
static int hf_openhpsdr_e_hps_fp_alex3 = -1;
static int hf_openhpsdr_e_hps_rp_alex0 = -1;
static int hf_openhpsdr_e_hps_rp_alex1 = -1;
static int hf_openhpsdr_e_hps_rp_alex2 = -1;
static int hf_openhpsdr_e_hps_rp_alex3 = -1;
static int hf_openhpsdr_e_hps_supp_vol = -1;
static int hf_openhpsdr_e_hps_user_adc3 = -1;
static int hf_openhpsdr_e_hps_user_adc2 = -1;
static int hf_openhpsdr_e_hps_user_adc1 = -1;
static int hf_openhpsdr_e_hps_user_adc0 = -1;
static int hf_openhpsdr_e_hps_user_logic0 = -1;
static int hf_openhpsdr_e_hps_user_logic1 = -1;
static int hf_openhpsdr_e_hps_user_logic2 = -1;
static int hf_openhpsdr_e_hps_user_logic3 = -1;
static int hf_openhpsdr_e_hps_user_logic4 = -1;
static int hf_openhpsdr_e_hps_user_logic5 = -1;
static int hf_openhpsdr_e_hps_user_logic6 = -1;
static int hf_openhpsdr_e_hps_user_logic7 = -1;

static int hf_openhpsdr_e_ducc_banner = -1;
static int hf_openhpsdr_e_ducc_sequence_num = -1;
static int hf_openhpsdr_e_ducc_dac_num = -1;
static int hf_openhpsdr_e_ducc_eer = -1;
static int hf_openhpsdr_e_ducc_cw = -1;
static int hf_openhpsdr_e_ducc_rev_cw = -1;
static int hf_openhpsdr_e_ducc_iambic = -1;
static int hf_openhpsdr_e_ducc_sidetone = -1;
static int hf_openhpsdr_e_ducc_cw_mode_b = -1;
static int hf_openhpsdr_e_ducc_cw_st_char_space = -1;
static int hf_openhpsdr_e_ducc_cw_breakin = -1;
static int hf_openhpsdr_e_ducc_cw_sidetone_level = -1;
static int hf_openhpsdr_e_ducc_cw_sidetone_freq = -1;
static int hf_openhpsdr_e_ducc_cw_keyer_speed = -1;
static int hf_openhpsdr_e_ducc_cw_keyer_weight = -1;
static int hf_openhpsdr_e_ducc_cw_hang_delay = -1;
static int hf_openhpsdr_e_ducc_rf_delay = -1;
static int hf_openhpsdr_e_ducc_duc0_sample = -1;
static int hf_openhpsdr_e_ducc_duc0_bits = -1;
static int hf_openhpsdr_e_ducc_duc0_phase_shift = -1;
static int hf_openhpsdr_e_ducc_line_in = -1;
static int hf_openhpsdr_e_ducc_mic_boost = -1;
static int hf_openhpsdr_e_ducc_orion_mic_ptt = -1;
static int hf_openhpsdr_e_ducc_orion_mic_ring_tip = -1;
static int hf_openhpsdr_e_ducc_orion_mic_bias = -1; 
static int hf_openhpsdr_e_ducc_line_in_gain = -1;
static int hf_openhpsdr_e_ducc_attn_adc0_duc0 = -1;

static int hf_openhpsdr_e_micl_banner = -1;
static int hf_openhpsdr_e_micl_sequence_num = -1;
static int hf_openhpsdr_e_micl_separator = -1;
static int hf_openhpsdr_e_micl_sample_idx = -1;
static int hf_openhpsdr_e_micl_sample = -1;

static int hf_openhpsdr_e_hpc_banner = -1;
static int hf_openhpsdr_e_hpc_sequence_num = -1;
static int hf_openhpsdr_e_hpc_run = -1;
static int hf_openhpsdr_e_hpc_ptt0 = -1;
static int hf_openhpsdr_e_hpc_ptt1 = -1;
static int hf_openhpsdr_e_hpc_ptt2 = -1;
static int hf_openhpsdr_e_hpc_ptt3 = -1;
static int hf_openhpsdr_e_hpc_cwx0 = -1;
static int hf_openhpsdr_e_hpc_dot = -1;
static int hf_openhpsdr_e_hpc_dash = -1;
static int hf_openhpsdr_e_hpc_cwx1 = -1;
static int hf_openhpsdr_e_hpc_cwx2 = -1;
static int hf_openhpsdr_e_hpc_cwx3 = -1;
static int hf_openhpsdr_e_hpc_ddc_fp_sub =-1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc0 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc1 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc2 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc3 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc4 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc5 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc6 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc7 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc8 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc9 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc10 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc11 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc12 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc13 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc14 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc15 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc16 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc17 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc18 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc19 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc20 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc21 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc22 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc23 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc24 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc25 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc26 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc27 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc28 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc29 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc30 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc31 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc32 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc33 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc34 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc35 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc36 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc37 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc38 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc39 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc40 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc41 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc42 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc43 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc44 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc45 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc46 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc47 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc48 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc49 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc50 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc51 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc52 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc53 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc54 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc55 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc56 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc57 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc58 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc59 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc60 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc61 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc62 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc63 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc64 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc65 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc66 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc67 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc68 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc69 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc70 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc71 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc72 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc73 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc74 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc75 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc76 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc77 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc78 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_ddc79 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_duc0 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_duc1 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_duc2 = -1;
static int hf_openhpsdr_e_hpc_freq_phase_duc3 = -1;
static int hf_openhpsdr_e_hpc_drive_duc0 = -1;
static int hf_openhpsdr_e_hpc_drive_duc1 = -1;
static int hf_openhpsdr_e_hpc_drive_duc2 = -1;
static int hf_openhpsdr_e_hpc_drive_duc3 = -1;
static int hf_openhpsdr_e_hpc_open_col0 = -1;
static int hf_openhpsdr_e_hpc_open_col1 = -1;
static int hf_openhpsdr_e_hpc_open_col2 = -1;
static int hf_openhpsdr_e_hpc_open_col3 = -1;
static int hf_openhpsdr_e_hpc_open_col4 = -1;
static int hf_openhpsdr_e_hpc_open_col5 = -1;
static int hf_openhpsdr_e_hpc_open_col6 = -1;
static int hf_openhpsdr_e_hpc_open_col7 = -1;
static int hf_openhpsdr_e_hpc_db9_out1 = -1;
static int hf_openhpsdr_e_hpc_db9_out2 = -1;
static int hf_openhpsdr_e_hpc_db9_out3 = -1;
static int hf_openhpsdr_e_hpc_db9_out4 = -1;
static int hf_openhpsdr_e_hpc_merc_att1 = -1;
static int hf_openhpsdr_e_hpc_merc_att2 = -1;
static int hf_openhpsdr_e_hpc_merc_att3 = -1;
static int hf_openhpsdr_e_hpc_merc_att4 = -1;
static int hf_openhpsdr_e_hpc_alex7 = -1;
static int hf_openhpsdr_e_hpc_alex6 = -1;
static int hf_openhpsdr_e_hpc_alex5 = -1;
static int hf_openhpsdr_e_hpc_alex4 = -1;
static int hf_openhpsdr_e_hpc_alex3 = -1;
static int hf_openhpsdr_e_hpc_alex2 = -1;
static int hf_openhpsdr_e_hpc_alex1 = -1;
static int hf_openhpsdr_e_hpc_alex0_sub = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_17_15 = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_12_10 = -1;
static int hf_openhpsdr_e_hpc_alex0_bypass = -1;
static int hf_openhpsdr_e_hpc_alex0_red_led1 = -1;
static int hf_openhpsdr_e_hpc_alex0_tx_rx = -1;
static int hf_openhpsdr_e_hpc_alex0_ant3 = -1;
static int hf_openhpsdr_e_hpc_alex0_ant2 = -1;
static int hf_openhpsdr_e_hpc_alex0_ant1 = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_160 = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_80 = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_60_40 = -1;
static int hf_openhpsdr_e_hpc_alex0_lpf_30_20 = -1;
static int hf_openhpsdr_e_hpc_alex0_yel_led1 = -1;
static int hf_openhpsdr_e_hpc_alex0_red_led0 = -1;
static int hf_openhpsdr_e_hpc_alex0_att_10 = -1;
static int hf_openhpsdr_e_hpc_alex0_att_20 = -1;
static int hf_openhpsdr_e_hpc_alex0_hf_bypass = -1;
static int hf_openhpsdr_e_hpc_alex0_ddc1_out = -1;
static int hf_openhpsdr_e_hpc_alex0_ddc1_in = -1;
static int hf_openhpsdr_e_hpc_alex0_ddc2_in = -1;
static int hf_openhpsdr_e_hpc_alex0_ddc_xvtr_in = -1;
static int hf_openhpsdr_e_hpc_alex0_hpf_1_5 = -1;
static int hf_openhpsdr_e_hpc_alex0_hpf_6_5 = -1;
static int hf_openhpsdr_e_hpc_alex0_hpf_9_5 = -1;
static int hf_openhpsdr_e_hpc_alex0_6m_amp = -1;
static int hf_openhpsdr_e_hpc_alex0_hpf_20 = -1;
static int hf_openhpsdr_e_hpc_alex0_hpf_13 = -1;
static int hf_openhpsdr_e_hpc_alex0_yel_led0 = -1;
static int hf_openhpsdr_e_hpc_att7 = -1;
static int hf_openhpsdr_e_hpc_att6 = -1;
static int hf_openhpsdr_e_hpc_att5 = -1;
static int hf_openhpsdr_e_hpc_att4 = -1;
static int hf_openhpsdr_e_hpc_att3 = -1;
static int hf_openhpsdr_e_hpc_att2 = -1;
static int hf_openhpsdr_e_hpc_att1 = -1;
static int hf_openhpsdr_e_hpc_att0 = -1;

static int hf_openhpsdr_e_wbd_banner = -1;
static int hf_openhpsdr_e_wbd_sequence_num = -1;
static int hf_openhpsdr_e_wbd_adc = -1;
static int hf_openhpsdr_e_wbd_separator = -1;
static int hf_openhpsdr_e_wbd_sample_idx = -1;
static int hf_openhpsdr_e_wbd_sample = -1;

static int hf_openhpsdr_e_ddca_banner = -1;
static int hf_openhpsdr_e_ddca_sequence_num = -1;
static int hf_openhpsdr_e_ddca_sample_bits = -1;
static int hf_openhpsdr_e_ddca_separator = -1;
static int hf_openhpsdr_e_ddca_sample_idx = -1;
static int hf_openhpsdr_e_ddca_l_sample = -1;
static int hf_openhpsdr_e_ddca_r_sample = -1;

static int hf_openhpsdr_e_duciq_banner = -1;
static int hf_openhpsdr_e_duciq_sequence_num = -1;
static int hf_openhpsdr_e_duciq_duc = -1;
static int hf_openhpsdr_e_duciq_sample_bits = -1;
static int hf_openhpsdr_e_duciq_separator = -1;
static int hf_openhpsdr_e_duciq_sample_idx = -1;
static int hf_openhpsdr_e_duciq_i_sample = -1;
static int hf_openhpsdr_e_duciq_q_sample = -1;

static int hf_openhpsdr_e_ddciq_banner = -1;
static int hf_openhpsdr_e_ddciq_sequence_num = -1;
static int hf_openhpsdr_e_ddciq_ddc = -1;
static int hf_openhpsdr_e_ddciq_time_stamp = -1;
static int hf_openhpsdr_e_ddciq_sample_bits = -1;
static int hf_openhpsdr_e_ddciq_samples_per_frame = -1;
static int hf_openhpsdr_e_ddciq_ethernet_frame_size = -1;
static int hf_openhpsdr_e_ddciq_separator = -1;
static int hf_openhpsdr_e_ddciq_sample_idx = -1;
static int hf_openhpsdr_e_ddciq_8b_i_sample = -1;
static int hf_openhpsdr_e_ddciq_8b_q_sample = -1;
static int hf_openhpsdr_e_ddciq_16b_i_sample = -1;
static int hf_openhpsdr_e_ddciq_16b_q_sample = -1;
static int hf_openhpsdr_e_ddciq_24b_i_sample = -1;
static int hf_openhpsdr_e_ddciq_24b_q_sample = -1;
static int hf_openhpsdr_e_ddciq_32b_i_sample = -1;
static int hf_openhpsdr_e_ddciq_32b_q_sample = -1;

static int hf_openhpsdr_e_mem_banner = -1;
static int hf_openhpsdr_e_mem_sequence_num = -1;
static int hf_openhpsdr_e_mem_separator = -1;
static int hf_openhpsdr_e_mem_idx = -1;
static int hf_openhpsdr_e_mem_address = -1;
static int hf_openhpsdr_e_mem_data = -1;

// Expert Items
static expert_field ei_cr_extra_length = EI_INIT;
static expert_field ei_cr_program_check_roll_over = EI_INIT;
static expert_field ei_ddciq_larger_then_mtu = EI_INIT;

// Preferences
static gboolean openhpsdr_e_strict_size = TRUE;
static gboolean openhpsdr_e_strict_pad = TRUE;
static gboolean openhpsdr_e_cr_strict_program_data_size = TRUE;
static gboolean openhpsdr_e_ddciq_mtu_check = TRUE;

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
static guint8  board_id = -1;

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

static const true_false_string lock_unlock = {
    "Locked",
    "Unlocked"
};

static const true_false_string orion_tip_ring = {
    "micPTT to Tip, Mic/Mic Bias to Ring",
    "micPTT to Ring, Mic/Mic Bias to Tip"
};

static const true_false_string host_hardware = {
    "Host",
    "Hardware"
};   

// The Windows build environment does not like to pull in the
// true_false_string structures from Wireshark source / dll 
// tfs.c. The true_false_string structure is defined in tfs.h.
// Tfs.h is pulled in via packet.h. 
// The true_false_string structures below are duplicates of 
// structures found in tfs.c
const true_false_string local_active_inactive = { "Active", "Inactive" };
const true_false_string local_set_notset = { "Set", "Not set" };
const true_false_string local_on_off = { "On", "Off" };
const true_false_string local_enabled_disabled = { "Enabled", "Disabled" };
const true_false_string local_disabled_enabled = { "Disabled", "Enabled" };



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
        &ett_openhpsdr_e_ddcc_ditram,
        &ett_openhpsdr_e_ddcc_state,
        &ett_openhpsdr_e_ddcc_config,
        &ett_openhpsdr_e_ddcc_sync,
        &ett_openhpsdr_e_ddcc_mux,
        &ett_openhpsdr_e_hps,
        &ett_openhpsdr_e_ducc,
        &ett_openhpsdr_e_micl,
        &ett_openhpsdr_e_hpc,
        &ett_openhpsdr_e_hpc_ddc_fp,
        &ett_openhpsdr_e_hpc_alex0,
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
       { &ei_ddciq_larger_then_mtu,
           { "openhpsdr-e.ei.ddciq.larger-then-mtu", PI_MALFORMED, PI_WARN,
             "Larger then maximum MTU", EXPFILL }
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
       { &hf_openhpsdr_e_ddcc_adc_num,
           { "Number of Supported ADC", "openhpsdr-e.ddcc.adc-num",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ditram_sub,
           { "DDC Command Dither Random Submenu" , "openhpsdr-e.ddcc.ditram-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither0,
           { "ADC 0 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither1,
           { "ADC 1 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither2,
           { "ADC 2 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither3,
           { "ADC 3 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither4,
           { "ADC 4 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither5,
           { "ADC 5 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither6,
           { "ADC 6 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-6",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_dither7,
           { "ADC 7 Dither" , "openhpsdr-e.cr.ddcc.adc-dither-7",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random0,
           { "ADC 0 Random" , "openhpsdr-e.cr.ddcc.adc-random-0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random1,
           { "ADC 1 Random" , "openhpsdr-e.cr.ddcc.adc-random-1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random2,
           { "ADC 2 Random" , "openhpsdr-e.cr.ddcc.adc-random-2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random3,
           { "ADC 3 Random" , "openhpsdr-e.cr.ddcc.adc-random-3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random4,
           { "ADC 4 Random" , "openhpsdr-e.cr.ddcc.adc-random-4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random5,
           { "ADC 5 Random" , "openhpsdr-e.cr.ddcc.adc-random-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random6,
           { "ADC 6 Random" , "openhpsdr-e.cr.ddcc.adc-random-6",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_adc_random7,
           { "ADC 7 Random" , "openhpsdr-e.cr.ddcc.adc-random-7",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_state_sub,
           { "DDC State Submenu" , "openhpsdr-e.ddcc.state-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc0,
           { "DDC  0" , "openhpsdr-e.cr.ddcc.ddc-0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc1,
           { "DDC  1" , "openhpsdr-e.cr.ddcc.ddc-1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc2,
           { "DDC  2" , "openhpsdr-e.cr.ddcc.ddc-2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc3,
           { "DDC  3" , "openhpsdr-e.cr.ddcc.ddc-3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc4,
           { "DDC  4" , "openhpsdr-e.cr.ddcc.ddc-4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc5,
           { "DDC  5" , "openhpsdr-e.cr.ddcc.ddc-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc6,
           { "DDC  6" , "openhpsdr-e.cr.ddcc.ddc-6",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc7,
           { "DDC  7" , "openhpsdr-e.cr.ddcc.ddc-7",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc8,
           { "DDC  8" , "openhpsdr-e.cr.ddcc.ddc-8",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc9,
           { "DDC  9" , "openhpsdr-e.cr.ddcc.ddc-9",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc10,
           { "DDC 10" , "openhpsdr-e.cr.ddcc.ddc-10",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc11,
           { "DDC 11" , "openhpsdr-e.cr.ddcc.ddc-11",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc12,
           { "DDC 12" , "openhpsdr-e.cr.ddcc.ddc-12",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc13,
           { "DDC 13" , "openhpsdr-e.cr.ddcc.ddc-13",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc14,
           { "DDC 14" , "openhpsdr-e.cr.ddcc.ddc-14",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc15,
           { "DDC 15" , "openhpsdr-e.cr.ddcc.ddc-15",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc16,
           { "DDC 16" , "openhpsdr-e.cr.ddcc.ddc-16",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc17,
           { "DDC 17" , "openhpsdr-e.cr.ddcc.ddc-17",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc18,
           { "DDC 18" , "openhpsdr-e.cr.ddcc.ddc-18",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc19,
           { "DDC 19" , "openhpsdr-e.cr.ddcc.ddc-19",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc20,
           { "DDC 20" , "openhpsdr-e.cr.ddcc.ddc-20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc21,
           { "DDC 21" , "openhpsdr-e.cr.ddcc.ddc-21",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc22,
           { "DDC 22" , "openhpsdr-e.cr.ddcc.ddc-22",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc23,
           { "DDC 23" , "openhpsdr-e.cr.ddcc.ddc-23",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc24,
           { "DDC 24" , "openhpsdr-e.cr.ddcc.ddc-24",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc25,
           { "DDC 25" , "openhpsdr-e.cr.ddcc.ddc-25",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc26,
           { "DDC 26" , "openhpsdr-e.cr.ddcc.ddc-26",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc27,
           { "DDC 27" , "openhpsdr-e.cr.ddcc.ddc-27",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc28,
           { "DDC 28" , "openhpsdr-e.cr.ddcc.ddc-28",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc29,
           { "DDC 29" , "openhpsdr-e.cr.ddcc.ddc-29",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc30,
           { "DDC 30" , "openhpsdr-e.cr.ddcc.ddc-30",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc31,
           { "DDC 31" , "openhpsdr-e.cr.ddcc.ddc-31",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc32,
           { "DDC 32" , "openhpsdr-e.cr.ddcc.ddc-32",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc33,
           { "DDC 33" , "openhpsdr-e.cr.ddcc.ddc-33",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc34,
           { "DDC 34" , "openhpsdr-e.cr.ddcc.ddc-34",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc35,
           { "DDC 35" , "openhpsdr-e.cr.ddcc.ddc-35",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc36,
           { "DDC 36" , "openhpsdr-e.cr.ddcc.ddc-36",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc37,
           { "DDC 37" , "openhpsdr-e.cr.ddcc.ddc-37",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc38,
           { "DDC 38" , "openhpsdr-e.cr.ddcc.ddc-38",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc39,
           { "DDC 39" , "openhpsdr-e.cr.ddcc.ddc-39",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc40,
           { "DDC 40" , "openhpsdr-e.cr.ddcc.ddc-40",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc41,
           { "DDC 41" , "openhpsdr-e.cr.ddcc.ddc-41",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc42,
           { "DDC 42" , "openhpsdr-e.cr.ddcc.ddc-42",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc43,
           { "DDC 43" , "openhpsdr-e.cr.ddcc.ddc-43",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc44,
           { "DDC 44" , "openhpsdr-e.cr.ddcc.ddc-44",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc45,
           { "DDC 45" , "openhpsdr-e.cr.ddcc.ddc-45",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc46,
           { "DDC 46" , "openhpsdr-e.cr.ddcc.ddc-46",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc47,
           { "DDC 47" , "openhpsdr-e.cr.ddcc.ddc-47",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc48,
           { "DDC 48" , "openhpsdr-e.cr.ddcc.ddc-48",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc49,
           { "DDC 49" , "openhpsdr-e.cr.ddcc.ddc-49",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc50,
           { "DDC 50" , "openhpsdr-e.cr.ddcc.ddc-50",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc51,
           { "DDC 51" , "openhpsdr-e.cr.ddcc.ddc-51",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc52,
           { "DDC 52" , "openhpsdr-e.cr.ddcc.ddc-52",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc53,
           { "DDC 53" , "openhpsdr-e.cr.ddcc.ddc-53",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc54,
           { "DDC 54" , "openhpsdr-e.cr.ddcc.ddc-54",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc55,
           { "DDC 55" , "openhpsdr-e.cr.ddcc.ddc-55",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc56,
           { "DDC 56" , "openhpsdr-e.cr.ddcc.ddc-56",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc57,
           { "DDC 57" , "openhpsdr-e.cr.ddcc.ddc-57",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc58,
           { "DDC 58" , "openhpsdr-e.cr.ddcc.ddc-58",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc59,
           { "DDC 59" , "openhpsdr-e.cr.ddcc.ddc-59",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc60,
           { "DDC 60" , "openhpsdr-e.cr.ddcc.ddc-60",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc61,
           { "DDC 61" , "openhpsdr-e.cr.ddcc.ddc-61",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc62,
           { "DDC 62" , "openhpsdr-e.cr.ddcc.ddc-62",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc63,
           { "DDC 63" , "openhpsdr-e.cr.ddcc.ddc-63",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc64,
           { "DDC 64" , "openhpsdr-e.cr.ddcc.ddc-64",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc65,
           { "DDC 65" , "openhpsdr-e.cr.ddcc.ddc-65",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc66,
           { "DDC 66" , "openhpsdr-e.cr.ddcc.ddc-66",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc67,
           { "DDC 67" , "openhpsdr-e.cr.ddcc.ddc-67",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc68,
           { "DDC 68" , "openhpsdr-e.cr.ddcc.ddc-68",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc69,
           { "DDC 69" , "openhpsdr-e.cr.ddcc.ddc-69",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc70,
           { "DDC 70" , "openhpsdr-e.cr.ddcc.ddc-70",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc71,
           { "DDC 71" , "openhpsdr-e.cr.ddcc.ddc-71",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc72,
           { "DDC 72" , "openhpsdr-e.cr.ddcc.ddc-72",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc73,
           { "DDC 73" , "openhpsdr-e.cr.ddcc.ddc-73",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc74,
           { "DDC 74" , "openhpsdr-e.cr.ddcc.ddc-74",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc75,
           { "DDC 75" , "openhpsdr-e.cr.ddcc.ddc-75",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc76,
           { "DDC 76" , "openhpsdr-e.cr.ddcc.ddc-76",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc77,
           { "DDC 77" , "openhpsdr-e.cr.ddcc.ddc-77",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc78,
           { "DDC 78" , "openhpsdr-e.cr.ddcc.ddc-78",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc79,
           { "DDC 79" , "openhpsdr-e.cr.ddcc.ddc-79",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_config_sub,
           { "DDC Configuration Submenu" , "openhpsdr-e.ddcc.config-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign0,
           { "DDC  0  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-0",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign1,
           { "DDC  1  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-1",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign2,
           { "DDC  2  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-2",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign3,
           { "DDC  3  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-3",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign4,
           { "DDC  4  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-4",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign5,
           { "DDC  5  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-5",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign6,
           { "DDC  6  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-6",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign7,
           { "DDC  7  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-7",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign8,
           { "DDC  8  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-8",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign9,
           { "DDC  9  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-9",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign10,
           { "DDC 10  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-10",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign11,
           { "DDC 11  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-11",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign12,
           { "DDC 12  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-12",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign13,
           { "DDC 13  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-13",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign14,
           { "DDC 14  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-14",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign15,
           { "DDC 15  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-15",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign16,
           { "DDC 16  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-16",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign17,
           { "DDC 17  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-17",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign18,
           { "DDC 18  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-18",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign19,
           { "DDC 19  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-19",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign20,
           { "DDC 20  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-20",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign21,
           { "DDC 21  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-21",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign22,
           { "DDC 22  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-22",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign23,
           { "DDC 23  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-23",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign24,
           { "DDC 24  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-24",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign25,
           { "DDC 25  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-25",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign26,
           { "DDC 26  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-26",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign27,
           { "DDC 27  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-27",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign28,
           { "DDC 28  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-28",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign29,
           { "DDC 29  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-29",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign30,
           { "DDC 30  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-30",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign31,
           { "DDC 31  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-31",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign32,
           { "DDC 32  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-32",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign33,
           { "DDC 33  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-33",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign34,
           { "DDC 34  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-34",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign35,
           { "DDC 35  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-35",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign36,
           { "DDC 36  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-36",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign37,
           { "DDC 37  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-37",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign38,
           { "DDC 38  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-38",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign39,
           { "DDC 39  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-39",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign40,
           { "DDC 40  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-40",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign41,
           { "DDC 41  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-41",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign42,
           { "DDC 42  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-42",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign43,
           { "DDC 43  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-43",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign44,
           { "DDC 44  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-44",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign45,
           { "DDC 45  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-45",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign46,
           { "DDC 46  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-46",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign47,
           { "DDC 47  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-47",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign48,
           { "DDC 48  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-48",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign49,
           { "DDC 49  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-49",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign50,
           { "DDC 50  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-50",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign51,
           { "DDC 51  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-51",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign52,
           { "DDC 52  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-52",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign53,
           { "DDC 53  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-53",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign54,
           { "DDC 54  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-54",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign55,
           { "DDC 55  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-55",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign56,
           { "DDC 56  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-56",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign57,
           { "DDC 57  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-57",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign58,
           { "DDC 58  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-58",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign59,
           { "DDC 59  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-59",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign60,
           { "DDC 60  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-60",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign61,
           { "DDC 61  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-61",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign62,
           { "DDC 62  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-62",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign63,
           { "DDC 63  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-63",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign64,
           { "DDC 64  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-64",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign65,
           { "DDC 65  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-65",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign66,
           { "DDC 66  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-66",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign67,
           { "DDC 67  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-67",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign68,
           { "DDC 68  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-68",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign69,
           { "DDC 69  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-69",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign70,
           { "DDC 70  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-70",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign71,
           { "DDC 71  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-71",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign72,
           { "DDC 72  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-72",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign73,
           { "DDC 73  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-73",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign74,
           { "DDC 74  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-74",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign75,
           { "DDC 75  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-75",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign76,
           { "DDC 76  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-76",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign77,
           { "DDC 77  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-77",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign78,
           { "DDC 78  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-78",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_asign79,
           { "DDC 79  ADC Assignment", "openhpsdr-e.cr.ddcc.ddc-asign-79",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate0,
           { "DDC  0     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-0",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate1,
           { "DDC  1     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-1",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate2,
           { "DDC  2     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-2",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate3,
           { "DDC  3     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-3",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate4,
           { "DDC  4     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-4",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate5,
           { "DDC  5     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-5",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate6,
           { "DDC  6     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-6",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate7,
           { "DDC  7     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-7",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate8,
           { "DDC  8     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-8",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate9,
           { "DDC  9     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-9",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate10,
           { "DDC 10     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-10",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate11,
           { "DDC 11     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-11",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate12,
           { "DDC 12     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-12",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate13,
           { "DDC 13     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-13",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate14,
           { "DDC 14     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-14",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate15,
           { "DDC 15     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-15",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate16,
           { "DDC 16     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-16",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate17,
           { "DDC 17     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-17",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate18,
           { "DDC 18     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-18",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate19,
           { "DDC 19     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-19",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate20,
           { "DDC 20     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-20",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate21,
           { "DDC 21     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-21",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate22,
           { "DDC 22     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-22",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate23,
           { "DDC 23     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-23",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate24,
           { "DDC 24     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-24",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate25,
           { "DDC 25     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-25",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate26,
           { "DDC 26     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-26",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate27,
           { "DDC 27     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-27",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate28,
           { "DDC 28     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-28",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate29,
           { "DDC 29     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-29",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate30,
           { "DDC 30     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-30",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate31,
           { "DDC 31     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-31",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate32,
           { "DDC 32     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-32",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate33,
           { "DDC 33     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-33",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate34,
           { "DDC 34     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-34",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate35,
           { "DDC 35     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-35",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate36,
           { "DDC 36     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-36",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate37,
           { "DDC 37     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-37",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate38,
           { "DDC 38     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-38",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate39,
           { "DDC 39     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-39",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate40,
           { "DDC 40     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-40",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate41,
           { "DDC 41     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-41",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate42,
           { "DDC 42     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-42",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate43,
           { "DDC 43     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-43",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate44,
           { "DDC 44     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-44",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate45,
           { "DDC 45     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-45",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate46,
           { "DDC 46     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-46",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate47,
           { "DDC 47     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-47",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate48,
           { "DDC 48     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-48",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate49,
           { "DDC 49     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-49",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate50,
           { "DDC 50     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-50",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate51,
           { "DDC 51     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-51",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate52,
           { "DDC 52     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-52",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate53,
           { "DDC 53     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-53",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate54,
           { "DDC 54     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-54",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate55,
           { "DDC 55     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-55",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate56,
           { "DDC 56     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-56",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate57,
           { "DDC 57     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-57",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate58,
           { "DDC 58     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-58",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate59,
           { "DDC 59     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-59",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate60,
           { "DDC 60     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-60",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate61,
           { "DDC 61     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-61",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate62,
           { "DDC 62     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-62",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate63,
           { "DDC 63     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-63",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate64,
           { "DDC 64     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-64",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate65,
           { "DDC 65     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-65",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate66,
           { "DDC 66     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-66",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate67,
           { "DDC 67     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-67",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate68,
           { "DDC 68     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-68",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate69,
           { "DDC 69     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-69",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate70,
           { "DDC 70     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-70",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate71,
           { "DDC 71     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-71",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate72,
           { "DDC 72     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-72",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate73,
           { "DDC 73     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-73",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate74,
           { "DDC 74     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-74",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate75,
           { "DDC 75     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-75",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate76,
           { "DDC 76     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-76",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate77,
           { "DDC 77     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-77",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate78,
           { "DDC 78     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-78",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_rate79,
           { "DDC 79     Sample Rate", "openhpsdr-e.cr.ddcc.ddc-rate-79",
             FT_UINT16, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_0,
           { "DDC  0       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-0",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_1,
           { "DDC  1       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-1",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_2,
           { "DDC  2       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-2",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_3,
           { "DDC  3       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-3",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_4,
           { "DDC  4       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-4",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_5,
           { "DDC  5       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-5",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_6,
           { "DDC  6       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-6",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_7,
           { "DDC  7       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-7",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_8,
           { "DDC  8       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-8",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_9,
           { "DDC  9       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-9",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_10,
           { "DDC 10       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-10",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_11,
           { "DDC 11       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-11",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_12,
           { "DDC 12       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-12",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_13,
           { "DDC 13       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-13",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_14,
           { "DDC 14       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-14",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_15,
           { "DDC 15       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-15",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_16,
           { "DDC 16       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-16",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_17,
           { "DDC 17       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-17",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_18,
           { "DDC 18       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-18",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_19,
           { "DDC 19       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-19",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_20,
           { "DDC 20       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-20",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_21,
           { "DDC 21       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-21",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_22,
           { "DDC 22       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-22",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_23,
           { "DDC 23       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-23",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_24,
           { "DDC 24       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-24",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_25,
           { "DDC 25       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-25",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_26,
           { "DDC 26       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-26",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_27,
           { "DDC 27       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-27",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_28,
           { "DDC 28       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-28",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_29,
           { "DDC 29       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-29",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_30,
           { "DDC 30       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-30",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_31,
           { "DDC 31       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-31",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_32,
           { "DDC 32       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-32",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_33,
           { "DDC 33       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-33",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_34,
           { "DDC 34       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-34",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_35,
           { "DDC 35       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-35",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_36,
           { "DDC 36       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-36",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_37,
           { "DDC 37       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-37",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_38,
           { "DDC 38       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-38",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_39,
           { "DDC 39       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-39",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_40,
           { "DDC 40       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-40",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_41,
           { "DDC 41       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-41",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_42,
           { "DDC 42       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-42",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_43,
           { "DDC 43       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-43",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_44,
           { "DDC 44       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-44",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_45,
           { "DDC 45       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-45",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_46,
           { "DDC 46       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-46",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_47,
           { "DDC 47       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-47",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_48,
           { "DDC 48       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-48",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_49,
           { "DDC 49       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-49",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_50,
           { "DDC 50       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-50",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_51,
           { "DDC 51       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-51",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_52,
           { "DDC 52       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-52",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_53,
           { "DDC 53       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-53",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_54,
           { "DDC 54       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-54",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_55,
           { "DDC 55       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-55",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_56,
           { "DDC 56       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-56",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_57,
           { "DDC 57       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-57",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_58,
           { "DDC 58       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-58",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_59,
           { "DDC 59       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-59",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_60,
           { "DDC 60       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-60",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_61,
           { "DDC 61       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-61",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_62,
           { "DDC 62       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-62",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_63,
           { "DDC 63       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-63",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_64,
           { "DDC 64       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-64",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_65,
           { "DDC 65       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-65",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_66,
           { "DDC 66       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-66",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_67,
           { "DDC 67       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-67",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_68,
           { "DDC 68       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-68",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_69,
           { "DDC 69       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-69",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_70,
           { "DDC 70       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-70",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_71,
           { "DDC 71       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-71",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_72,
           { "DDC 72       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-72",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_73,
           { "DDC 73       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-73",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_74,
           { "DDC 74       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-74",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_75,
           { "DDC 75       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-75",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_76,
           { "DDC 76       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-76",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_77,
           { "DDC 77       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-77",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_78,
           { "DDC 78       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-78",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic1_79,
           { "DDC 79       CIC1 Rate", "openhpsdr-e.cr.ddcc.ddc-cic1-79",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_0,
           { "DDC  0       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-0",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_1,
           { "DDC  1       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-1",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_2,
           { "DDC  2       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-2",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_3,
           { "DDC  3       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-3",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_4,
           { "DDC  4       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-4",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_5,
           { "DDC  5       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-5",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_6,
           { "DDC  6       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-6",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_7,
           { "DDC  7       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-7",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_8,
           { "DDC  8       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-8",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_9,
           { "DDC  9       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-9",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_10,
           { "DDC 10       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-10",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_11,
           { "DDC 11       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-11",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_12,
           { "DDC 12       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-12",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_13,
           { "DDC 13       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-13",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_14,
           { "DDC 14       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-14",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_15,
           { "DDC 15       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-15",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_16,
           { "DDC 16       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-16",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_17,
           { "DDC 17       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-17",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_18,
           { "DDC 18       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-18",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_19,
           { "DDC 19       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-19",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_20,
           { "DDC 20       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-20",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_21,
           { "DDC 21       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-21",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_22,
           { "DDC 22       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-22",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_23,
           { "DDC 23       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-23",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_24,
           { "DDC 24       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-24",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_25,
           { "DDC 25       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-25",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_26,
           { "DDC 26       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-26",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_27,
           { "DDC 27       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-27",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_28,
           { "DDC 28       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-28",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_29,
           { "DDC 29       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-29",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_30,
           { "DDC 30       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-30",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_31,
           { "DDC 31       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-31",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_32,
           { "DDC 32       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-32",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_33,
           { "DDC 33       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-33",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_34,
           { "DDC 34       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-34",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_35,
           { "DDC 35       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-35",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_36,
           { "DDC 36       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-36",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_37,
           { "DDC 37       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-37",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_38,
           { "DDC 38       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-38",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_39,
           { "DDC 39       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-39",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_40,
           { "DDC 40       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-40",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_41,
           { "DDC 41       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-41",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_42,
           { "DDC 42       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-42",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_43,
           { "DDC 43       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-43",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_44,
           { "DDC 44       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-44",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_45,
           { "DDC 45       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-45",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_46,
           { "DDC 46       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-46",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_47,
           { "DDC 47       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-47",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_48,
           { "DDC 48       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-48",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_49,
           { "DDC 49       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-49",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_50,
           { "DDC 50       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-50",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_51,
           { "DDC 51       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-51",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_52,
           { "DDC 52       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-52",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_53,
           { "DDC 53       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-53",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_54,
           { "DDC 54       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-54",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_55,
           { "DDC 55       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-55",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_56,
           { "DDC 56       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-56",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_57,
           { "DDC 57       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-57",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_58,
           { "DDC 58       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-58",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_59,
           { "DDC 59       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-59",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_60,
           { "DDC 60       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-60",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_61,
           { "DDC 61       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-61",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_62,
           { "DDC 62       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-62",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_63,
           { "DDC 63       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-63",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_64,
           { "DDC 64       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-64",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_65,
           { "DDC 65       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-65",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_66,
           { "DDC 66       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-66",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_67,
           { "DDC 67       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-67",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_68,
           { "DDC 68       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-68",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_69,
           { "DDC 69       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-69",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_70,
           { "DDC 70       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-70",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_71,
           { "DDC 71       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-71",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_72,
           { "DDC 72       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-72",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_73,
           { "DDC 73       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-73",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_74,
           { "DDC 74       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-74",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_75,
           { "DDC 75       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-75",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_76,
           { "DDC 76       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-76",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_77,
           { "DDC 77       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-77",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_78,
           { "DDC 78       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-78",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_cic2_79,
           { "DDC 79       CIC2 Rate", "openhpsdr-e.cr.ddcc.ddc-cic2-79",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size0,
           { "DDC  0 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-0",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size1,
           { "DDC  1 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-1",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size2,
           { "DDC  2 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-2",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size3,
           { "DDC  3 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-3",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size4,
           { "DDC  4 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-4",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size5,
           { "DDC  5 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-5",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size6,
           { "DDC  6 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-6",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size7,
           { "DDC  7 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-7",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size8,
           { "DDC  8 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-8",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size9,
           { "DDC  9 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-9",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size10,
           { "DDC 10 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-10",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size11,
           { "DDC 11 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-11",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size12,
           { "DDC 12 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-12",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size13,
           { "DDC 13 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-13",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size14,
           { "DDC 14 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-14",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size15,
           { "DDC 15 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-15",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size16,
           { "DDC 16 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-16",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size17,
           { "DDC 17 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-17",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size18,
           { "DDC 18 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-18",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size19,
           { "DDC 19 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-19",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size20,
           { "DDC 20 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-20",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size21,
           { "DDC 21 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-21",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size22,
           { "DDC 22 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-22",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size23,
           { "DDC 23 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-23",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size24,
           { "DDC 24 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-24",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size25,
           { "DDC 25 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-25",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size26,
           { "DDC 26 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-26",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size27,
           { "DDC 27 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-27",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size28,
           { "DDC 28 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-28",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size29,
           { "DDC 29 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-29",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size30,
           { "DDC 30 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-30",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size31,
           { "DDC 31 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-31",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size32,
           { "DDC 32 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-32",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size33,
           { "DDC 33 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-33",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size34,
           { "DDC 34 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-34",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size35,
           { "DDC 35 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-35",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size36,
           { "DDC 36 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-36",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size37,
           { "DDC 37 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-37",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size38,
           { "DDC 38 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-38",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size39,
           { "DDC 39 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-39",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size40,
           { "DDC 40 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-40",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size41,
           { "DDC 41 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-41",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size42,
           { "DDC 42 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-42",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size43,
           { "DDC 43 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-43",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size44,
           { "DDC 44 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-44",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size45,
           { "DDC 45 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-45",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size46,
           { "DDC 46 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-46",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size47,
           { "DDC 47 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-47",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size48,
           { "DDC 48 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-48",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size49,
           { "DDC 49 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-49",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size50,
           { "DDC 50 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-50",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size51,
           { "DDC 51 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-51",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size52,
           { "DDC 52 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-52",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size53,
           { "DDC 53 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-53",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size54,
           { "DDC 54 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-54",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size55,
           { "DDC 55 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-55",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size56,
           { "DDC 56 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-56",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size57,
           { "DDC 57 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-57",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size58,
           { "DDC 58 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-58",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size59,
           { "DDC 59 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-59",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size60,
           { "DDC 60 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-60",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size61,
           { "DDC 61 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-61",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size62,
           { "DDC 62 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-62",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size63,
           { "DDC 63 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-63",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size64,
           { "DDC 64 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-64",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size65,
           { "DDC 65 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-65",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size66,
           { "DDC 66 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-66",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size67,
           { "DDC 67 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-67",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size68,
           { "DDC 68 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-68",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size69,
           { "DDC 69 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-69",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size70,
           { "DDC 70 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-70",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size71,
           { "DDC 71 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-71",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size72,
           { "DDC 72 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-72",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size73,
           { "DDC 73 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-73",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size74,
           { "DDC 74 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-74",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size75,
           { "DDC 75 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-75",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size76,
           { "DDC 76 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-76",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size77,
           { "DDC 77 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-77",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size78,
           { "DDC 78 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-78",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_size79,
           { "DDC 79 I&Q Sample Size", "openhpsdr-e.cr.ddcc.ddc-size-79",
             FT_UINT8, BASE_DEC,
             NULL, ZERO_MASK,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_sync_sub,
           { "DDC Sunc Submenu" , "openhpsdr-e.ddcc.sync-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_0,
           { "DDC 0 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_1,
           { "DDC 1 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_2,
           { "DDC 2 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_3,
           { "DDC 3 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_4,
           { "DDC 4 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_5,
           { "DDC 5 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_6,
           { "DDC 6 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_7,
           { "DDC 7 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_8,
           { "DDC 8 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_9,
           { "DDC 9 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_10,
           { "DDC 10 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_11,
           { "DDC 11 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_12,
           { "DDC 12 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_13,
           { "DDC 13 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_14,
           { "DDC 14 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_15,
           { "DDC 15 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_16,
           { "DDC 16 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_17,
           { "DDC 17 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_18,
           { "DDC 18 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_19,
           { "DDC 19 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_20,
           { "DDC 20 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_21,
           { "DDC 21 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_22,
           { "DDC 22 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_23,
           { "DDC 23 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_24,
           { "DDC 24 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_25,
           { "DDC 25 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_26,
           { "DDC 26 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_27,
           { "DDC 27 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_28,
           { "DDC 28 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_29,
           { "DDC 29 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_30,
           { "DDC 30 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_31,
           { "DDC 31 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_32,
           { "DDC 32 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_33,
           { "DDC 33 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_34,
           { "DDC 34 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_35,
           { "DDC 35 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_36,
           { "DDC 36 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_37,
           { "DDC 37 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_38,
           { "DDC 38 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_39,
           { "DDC 39 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_40,
           { "DDC 40 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_41,
           { "DDC 41 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_42,
           { "DDC 42 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_43,
           { "DDC 43 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_44,
           { "DDC 44 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_45,
           { "DDC 45 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_46,
           { "DDC 46 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_47,
           { "DDC 47 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_48,
           { "DDC 48 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_49,
           { "DDC 49 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_50,
           { "DDC 50 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_51,
           { "DDC 51 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_52,
           { "DDC 52 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_53,
           { "DDC 53 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_54,
           { "DDC 54 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_55,
           { "DDC 55 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_56,
           { "DDC 56 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_57,
           { "DDC 57 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_58,
           { "DDC 58 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_59,
           { "DDC 59 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_60,
           { "DDC 60 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_61,
           { "DDC 61 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_62,
           { "DDC 62 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_63,
           { "DDC 63 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_64,
           { "DDC 64 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_65,
           { "DDC 65 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_66,
           { "DDC 66 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_67,
           { "DDC 67 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_68,
           { "DDC 68 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_69,
           { "DDC 69 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_70,
           { "DDC 70 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_71,
           { "DDC 71 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_72,
           { "DDC 72 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_73,
           { "DDC 73 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_74,
           { "DDC 74 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_75,
           { "DDC 75 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_76,
           { "DDC 76 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_77,
           { "DDC 77 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_78,
           { "DDC 78 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync0_79,
           { "DDC 79 Synchronized With DDC 0", "openhpsdr-e.cr.ddcc.ddc-sync0-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_0,
           { "DDC 0 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_1,
           { "DDC 1 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_2,
           { "DDC 2 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_3,
           { "DDC 3 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_4,
           { "DDC 4 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_5,
           { "DDC 5 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_6,
           { "DDC 6 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_7,
           { "DDC 7 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_8,
           { "DDC 8 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_9,
           { "DDC 9 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_10,
           { "DDC 10 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_11,
           { "DDC 11 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_12,
           { "DDC 12 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_13,
           { "DDC 13 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_14,
           { "DDC 14 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_15,
           { "DDC 15 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_16,
           { "DDC 16 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_17,
           { "DDC 17 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_18,
           { "DDC 18 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_19,
           { "DDC 19 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_20,
           { "DDC 20 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_21,
           { "DDC 21 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_22,
           { "DDC 22 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_23,
           { "DDC 23 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_24,
           { "DDC 24 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_25,
           { "DDC 25 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_26,
           { "DDC 26 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_27,
           { "DDC 27 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_28,
           { "DDC 28 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_29,
           { "DDC 29 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_30,
           { "DDC 30 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_31,
           { "DDC 31 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_32,
           { "DDC 32 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_33,
           { "DDC 33 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_34,
           { "DDC 34 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_35,
           { "DDC 35 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_36,
           { "DDC 36 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_37,
           { "DDC 37 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_38,
           { "DDC 38 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_39,
           { "DDC 39 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_40,
           { "DDC 40 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_41,
           { "DDC 41 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_42,
           { "DDC 42 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_43,
           { "DDC 43 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_44,
           { "DDC 44 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_45,
           { "DDC 45 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_46,
           { "DDC 46 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_47,
           { "DDC 47 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_48,
           { "DDC 48 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_49,
           { "DDC 49 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_50,
           { "DDC 50 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_51,
           { "DDC 51 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_52,
           { "DDC 52 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_53,
           { "DDC 53 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_54,
           { "DDC 54 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_55,
           { "DDC 55 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_56,
           { "DDC 56 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_57,
           { "DDC 57 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_58,
           { "DDC 58 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_59,
           { "DDC 59 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_60,
           { "DDC 60 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_61,
           { "DDC 61 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_62,
           { "DDC 62 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_63,
           { "DDC 63 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_64,
           { "DDC 64 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_65,
           { "DDC 65 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_66,
           { "DDC 66 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_67,
           { "DDC 67 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_68,
           { "DDC 68 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_69,
           { "DDC 69 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_70,
           { "DDC 70 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_71,
           { "DDC 71 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_72,
           { "DDC 72 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_73,
           { "DDC 73 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_74,
           { "DDC 74 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_75,
           { "DDC 75 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_76,
           { "DDC 76 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_77,
           { "DDC 77 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_78,
           { "DDC 78 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync1_79,
           { "DDC 79 Synchronized With DDC 1", "openhpsdr-e.cr.ddcc.ddc-sync1-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_0,
           { "DDC 0 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_1,
           { "DDC 1 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_2,
           { "DDC 2 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_3,
           { "DDC 3 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_4,
           { "DDC 4 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_5,
           { "DDC 5 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_6,
           { "DDC 6 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_7,
           { "DDC 7 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_8,
           { "DDC 8 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_9,
           { "DDC 9 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_10,
           { "DDC 10 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_11,
           { "DDC 11 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_12,
           { "DDC 12 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_13,
           { "DDC 13 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_14,
           { "DDC 14 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_15,
           { "DDC 15 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_16,
           { "DDC 16 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_17,
           { "DDC 17 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_18,
           { "DDC 18 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_19,
           { "DDC 19 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_20,
           { "DDC 20 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_21,
           { "DDC 21 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_22,
           { "DDC 22 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_23,
           { "DDC 23 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_24,
           { "DDC 24 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_25,
           { "DDC 25 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_26,
           { "DDC 26 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_27,
           { "DDC 27 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_28,
           { "DDC 28 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_29,
           { "DDC 29 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_30,
           { "DDC 30 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_31,
           { "DDC 31 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_32,
           { "DDC 32 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_33,
           { "DDC 33 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_34,
           { "DDC 34 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_35,
           { "DDC 35 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_36,
           { "DDC 36 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_37,
           { "DDC 37 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_38,
           { "DDC 38 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_39,
           { "DDC 39 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_40,
           { "DDC 40 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_41,
           { "DDC 41 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_42,
           { "DDC 42 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_43,
           { "DDC 43 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_44,
           { "DDC 44 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_45,
           { "DDC 45 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_46,
           { "DDC 46 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_47,
           { "DDC 47 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_48,
           { "DDC 48 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_49,
           { "DDC 49 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_50,
           { "DDC 50 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_51,
           { "DDC 51 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_52,
           { "DDC 52 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_53,
           { "DDC 53 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_54,
           { "DDC 54 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_55,
           { "DDC 55 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_56,
           { "DDC 56 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_57,
           { "DDC 57 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_58,
           { "DDC 58 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_59,
           { "DDC 59 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_60,
           { "DDC 60 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_61,
           { "DDC 61 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_62,
           { "DDC 62 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_63,
           { "DDC 63 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_64,
           { "DDC 64 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_65,
           { "DDC 65 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_66,
           { "DDC 66 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_67,
           { "DDC 67 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_68,
           { "DDC 68 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_69,
           { "DDC 69 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_70,
           { "DDC 70 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_71,
           { "DDC 71 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_72,
           { "DDC 72 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_73,
           { "DDC 73 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_74,
           { "DDC 74 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_75,
           { "DDC 75 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_76,
           { "DDC 76 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_77,
           { "DDC 77 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_78,
           { "DDC 78 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync2_79,
           { "DDC 79 Synchronized With DDC 2", "openhpsdr-e.cr.ddcc.ddc-sync2-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_0,
           { "DDC 0 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_1,
           { "DDC 1 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_2,
           { "DDC 2 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_3,
           { "DDC 3 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_4,
           { "DDC 4 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_5,
           { "DDC 5 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_6,
           { "DDC 6 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_7,
           { "DDC 7 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_8,
           { "DDC 8 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_9,
           { "DDC 9 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_10,
           { "DDC 10 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_11,
           { "DDC 11 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_12,
           { "DDC 12 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_13,
           { "DDC 13 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_14,
           { "DDC 14 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_15,
           { "DDC 15 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_16,
           { "DDC 16 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_17,
           { "DDC 17 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_18,
           { "DDC 18 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_19,
           { "DDC 19 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_20,
           { "DDC 20 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_21,
           { "DDC 21 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_22,
           { "DDC 22 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_23,
           { "DDC 23 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_24,
           { "DDC 24 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_25,
           { "DDC 25 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_26,
           { "DDC 26 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_27,
           { "DDC 27 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_28,
           { "DDC 28 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_29,
           { "DDC 29 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_30,
           { "DDC 30 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_31,
           { "DDC 31 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_32,
           { "DDC 32 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_33,
           { "DDC 33 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_34,
           { "DDC 34 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_35,
           { "DDC 35 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_36,
           { "DDC 36 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_37,
           { "DDC 37 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_38,
           { "DDC 38 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_39,
           { "DDC 39 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_40,
           { "DDC 40 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_41,
           { "DDC 41 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_42,
           { "DDC 42 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_43,
           { "DDC 43 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_44,
           { "DDC 44 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_45,
           { "DDC 45 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_46,
           { "DDC 46 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_47,
           { "DDC 47 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_48,
           { "DDC 48 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_49,
           { "DDC 49 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_50,
           { "DDC 50 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_51,
           { "DDC 51 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_52,
           { "DDC 52 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_53,
           { "DDC 53 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_54,
           { "DDC 54 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_55,
           { "DDC 55 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_56,
           { "DDC 56 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_57,
           { "DDC 57 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_58,
           { "DDC 58 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_59,
           { "DDC 59 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_60,
           { "DDC 60 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_61,
           { "DDC 61 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_62,
           { "DDC 62 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_63,
           { "DDC 63 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_64,
           { "DDC 64 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_65,
           { "DDC 65 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_66,
           { "DDC 66 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_67,
           { "DDC 67 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_68,
           { "DDC 68 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_69,
           { "DDC 69 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_70,
           { "DDC 70 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_71,
           { "DDC 71 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_72,
           { "DDC 72 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_73,
           { "DDC 73 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_74,
           { "DDC 74 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_75,
           { "DDC 75 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_76,
           { "DDC 76 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_77,
           { "DDC 77 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_78,
           { "DDC 78 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync3_79,
           { "DDC 79 Synchronized With DDC 3", "openhpsdr-e.cr.ddcc.ddc-sync3-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_0,
           { "DDC 0 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_1,
           { "DDC 1 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_2,
           { "DDC 2 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_3,
           { "DDC 3 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_4,
           { "DDC 4 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_5,
           { "DDC 5 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_6,
           { "DDC 6 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_7,
           { "DDC 7 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_8,
           { "DDC 8 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_9,
           { "DDC 9 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_10,
           { "DDC 10 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_11,
           { "DDC 11 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_12,
           { "DDC 12 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_13,
           { "DDC 13 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_14,
           { "DDC 14 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_15,
           { "DDC 15 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_16,
           { "DDC 16 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_17,
           { "DDC 17 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_18,
           { "DDC 18 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_19,
           { "DDC 19 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_20,
           { "DDC 20 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_21,
           { "DDC 21 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_22,
           { "DDC 22 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_23,
           { "DDC 23 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_24,
           { "DDC 24 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_25,
           { "DDC 25 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_26,
           { "DDC 26 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_27,
           { "DDC 27 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_28,
           { "DDC 28 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_29,
           { "DDC 29 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_30,
           { "DDC 30 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_31,
           { "DDC 31 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_32,
           { "DDC 32 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_33,
           { "DDC 33 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_34,
           { "DDC 34 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_35,
           { "DDC 35 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_36,
           { "DDC 36 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_37,
           { "DDC 37 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_38,
           { "DDC 38 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_39,
           { "DDC 39 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_40,
           { "DDC 40 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_41,
           { "DDC 41 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_42,
           { "DDC 42 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_43,
           { "DDC 43 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_44,
           { "DDC 44 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_45,
           { "DDC 45 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_46,
           { "DDC 46 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_47,
           { "DDC 47 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_48,
           { "DDC 48 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_49,
           { "DDC 49 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_50,
           { "DDC 50 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_51,
           { "DDC 51 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_52,
           { "DDC 52 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_53,
           { "DDC 53 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_54,
           { "DDC 54 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_55,
           { "DDC 55 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_56,
           { "DDC 56 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_57,
           { "DDC 57 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_58,
           { "DDC 58 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_59,
           { "DDC 59 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_60,
           { "DDC 60 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_61,
           { "DDC 61 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_62,
           { "DDC 62 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_63,
           { "DDC 63 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_64,
           { "DDC 64 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_65,
           { "DDC 65 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_66,
           { "DDC 66 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_67,
           { "DDC 67 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_68,
           { "DDC 68 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_69,
           { "DDC 69 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_70,
           { "DDC 70 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_71,
           { "DDC 71 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_72,
           { "DDC 72 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_73,
           { "DDC 73 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_74,
           { "DDC 74 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_75,
           { "DDC 75 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_76,
           { "DDC 76 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_77,
           { "DDC 77 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_78,
           { "DDC 78 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync4_79,
           { "DDC 79 Synchronized With DDC 4", "openhpsdr-e.cr.ddcc.ddc-sync4-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_0,
           { "DDC 0 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_1,
           { "DDC 1 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_2,
           { "DDC 2 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_3,
           { "DDC 3 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_4,
           { "DDC 4 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_5,
           { "DDC 5 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_6,
           { "DDC 6 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_7,
           { "DDC 7 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_8,
           { "DDC 8 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_9,
           { "DDC 9 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_10,
           { "DDC 10 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_11,
           { "DDC 11 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_12,
           { "DDC 12 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_13,
           { "DDC 13 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_14,
           { "DDC 14 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_15,
           { "DDC 15 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_16,
           { "DDC 16 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_17,
           { "DDC 17 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_18,
           { "DDC 18 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_19,
           { "DDC 19 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_20,
           { "DDC 20 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_21,
           { "DDC 21 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_22,
           { "DDC 22 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_23,
           { "DDC 23 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_24,
           { "DDC 24 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_25,
           { "DDC 25 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_26,
           { "DDC 26 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_27,
           { "DDC 27 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_28,
           { "DDC 28 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_29,
           { "DDC 29 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_30,
           { "DDC 30 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_31,
           { "DDC 31 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_32,
           { "DDC 32 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_33,
           { "DDC 33 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_34,
           { "DDC 34 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_35,
           { "DDC 35 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_36,
           { "DDC 36 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_37,
           { "DDC 37 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_38,
           { "DDC 38 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_39,
           { "DDC 39 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_40,
           { "DDC 40 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_41,
           { "DDC 41 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_42,
           { "DDC 42 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_43,
           { "DDC 43 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_44,
           { "DDC 44 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_45,
           { "DDC 45 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_46,
           { "DDC 46 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_47,
           { "DDC 47 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_48,
           { "DDC 48 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_49,
           { "DDC 49 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_50,
           { "DDC 50 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_51,
           { "DDC 51 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_52,
           { "DDC 52 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_53,
           { "DDC 53 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_54,
           { "DDC 54 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_55,
           { "DDC 55 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_56,
           { "DDC 56 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_57,
           { "DDC 57 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_58,
           { "DDC 58 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_59,
           { "DDC 59 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_60,
           { "DDC 60 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_61,
           { "DDC 61 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_62,
           { "DDC 62 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_63,
           { "DDC 63 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_64,
           { "DDC 64 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_65,
           { "DDC 65 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_66,
           { "DDC 66 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_67,
           { "DDC 67 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_68,
           { "DDC 68 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_69,
           { "DDC 69 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_70,
           { "DDC 70 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_71,
           { "DDC 71 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_72,
           { "DDC 72 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_73,
           { "DDC 73 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_74,
           { "DDC 74 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_75,
           { "DDC 75 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_76,
           { "DDC 76 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_77,
           { "DDC 77 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_78,
           { "DDC 78 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync5_79,
           { "DDC 79 Synchronized With DDC 5", "openhpsdr-e.cr.ddcc.ddc-sync5-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_0,
           { "DDC 0 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_1,
           { "DDC 1 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_2,
           { "DDC 2 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_3,
           { "DDC 3 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_4,
           { "DDC 4 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_5,
           { "DDC 5 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_6,
           { "DDC 6 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_7,
           { "DDC 7 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_8,
           { "DDC 8 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_9,
           { "DDC 9 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_10,
           { "DDC 10 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_11,
           { "DDC 11 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_12,
           { "DDC 12 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_13,
           { "DDC 13 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_14,
           { "DDC 14 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_15,
           { "DDC 15 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_16,
           { "DDC 16 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_17,
           { "DDC 17 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_18,
           { "DDC 18 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_19,
           { "DDC 19 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_20,
           { "DDC 20 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_21,
           { "DDC 21 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_22,
           { "DDC 22 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_23,
           { "DDC 23 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_24,
           { "DDC 24 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_25,
           { "DDC 25 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_26,
           { "DDC 26 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_27,
           { "DDC 27 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_28,
           { "DDC 28 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_29,
           { "DDC 29 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_30,
           { "DDC 30 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_31,
           { "DDC 31 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_32,
           { "DDC 32 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_33,
           { "DDC 33 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_34,
           { "DDC 34 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_35,
           { "DDC 35 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_36,
           { "DDC 36 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_37,
           { "DDC 37 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_38,
           { "DDC 38 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_39,
           { "DDC 39 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_40,
           { "DDC 40 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_41,
           { "DDC 41 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_42,
           { "DDC 42 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_43,
           { "DDC 43 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_44,
           { "DDC 44 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_45,
           { "DDC 45 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_46,
           { "DDC 46 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_47,
           { "DDC 47 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_48,
           { "DDC 48 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_49,
           { "DDC 49 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_50,
           { "DDC 50 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_51,
           { "DDC 51 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_52,
           { "DDC 52 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_53,
           { "DDC 53 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_54,
           { "DDC 54 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_55,
           { "DDC 55 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_56,
           { "DDC 56 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_57,
           { "DDC 57 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_58,
           { "DDC 58 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_59,
           { "DDC 59 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_60,
           { "DDC 60 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_61,
           { "DDC 61 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_62,
           { "DDC 62 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_63,
           { "DDC 63 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_64,
           { "DDC 64 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_65,
           { "DDC 65 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_66,
           { "DDC 66 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_67,
           { "DDC 67 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_68,
           { "DDC 68 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_69,
           { "DDC 69 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_70,
           { "DDC 70 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_71,
           { "DDC 71 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_72,
           { "DDC 72 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_73,
           { "DDC 73 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_74,
           { "DDC 74 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_75,
           { "DDC 75 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_76,
           { "DDC 76 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_77,
           { "DDC 77 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_78,
           { "DDC 78 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync6_79,
           { "DDC 79 Synchronized With DDC 6", "openhpsdr-e.cr.ddcc.ddc-sync6-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_0,
           { "DDC 0 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_1,
           { "DDC 1 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_2,
           { "DDC 2 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_3,
           { "DDC 3 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_4,
           { "DDC 4 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_5,
           { "DDC 5 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_6,
           { "DDC 6 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_7,
           { "DDC 7 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_8,
           { "DDC 8 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-8",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_9,
           { "DDC 9 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-9",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_10,
           { "DDC 10 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-10",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_11,
           { "DDC 11 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-11",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_12,
           { "DDC 12 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-12",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_13,
           { "DDC 13 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-13",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_14,
           { "DDC 14 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-14",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_15,
           { "DDC 15 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-15",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_16,
           { "DDC 16 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-16",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_17,
           { "DDC 17 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-17",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_18,
           { "DDC 18 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-18",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_19,
           { "DDC 19 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-19",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_20,
           { "DDC 20 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-20",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_21,
           { "DDC 21 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-21",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_22,
           { "DDC 22 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-22",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_23,
           { "DDC 23 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-23",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_24,
           { "DDC 24 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-24",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_25,
           { "DDC 25 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-25",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_26,
           { "DDC 26 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-26",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_27,
           { "DDC 27 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-27",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_28,
           { "DDC 28 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-28",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_29,
           { "DDC 29 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-29",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_30,
           { "DDC 30 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-30",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_31,
           { "DDC 31 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-31",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_32,
           { "DDC 32 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-32",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_33,
           { "DDC 33 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-33",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_34,
           { "DDC 34 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-34",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_35,
           { "DDC 35 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-35",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_36,
           { "DDC 36 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-36",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_37,
           { "DDC 37 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-37",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_38,
           { "DDC 38 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-38",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_39,
           { "DDC 39 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-39",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_40,
           { "DDC 40 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-40",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_41,
           { "DDC 41 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-41",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_42,
           { "DDC 42 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-42",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_43,
           { "DDC 43 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-43",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_44,
           { "DDC 44 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-44",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_45,
           { "DDC 45 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-45",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_46,
           { "DDC 46 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-46",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_47,
           { "DDC 47 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-47",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_48,
           { "DDC 48 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-48",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_49,
           { "DDC 49 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-49",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_50,
           { "DDC 50 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-50",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_51,
           { "DDC 51 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-51",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_52,
           { "DDC 52 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-52",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_53,
           { "DDC 53 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-53",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_54,
           { "DDC 54 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-54",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_55,
           { "DDC 55 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-55",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_56,
           { "DDC 56 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-56",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_57,
           { "DDC 57 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-57",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_58,
           { "DDC 58 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-58",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_59,
           { "DDC 59 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-59",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_60,
           { "DDC 60 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-60",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_61,
           { "DDC 61 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-61",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_62,
           { "DDC 62 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-62",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_63,
           { "DDC 63 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-63",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_64,
           { "DDC 64 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-64",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_65,
           { "DDC 65 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-65",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_66,
           { "DDC 66 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-66",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_67,
           { "DDC 67 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-67",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_68,
           { "DDC 68 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-68",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_69,
           { "DDC 69 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-69",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_70,
           { "DDC 70 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-70",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_71,
           { "DDC 71 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-71",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_72,
           { "DDC 72 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-72",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_73,
           { "DDC 73 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-73",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_74,
           { "DDC 74 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-74",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_75,
           { "DDC 75 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-75",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_76,
           { "DDC 76 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-76",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_77,
           { "DDC 77 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-77",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_78,
           { "DDC 78 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-78",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_sync7_79,
           { "DDC 79 Synchronized With DDC 7", "openhpsdr-e.cr.ddcc.ddc-sync7-79",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_mux_sub,
           { "DDC Multiplex Submenu" , "openhpsdr-e.ddcc.mux-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux0,
           { "DDC 0 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux1,
           { "DDC 1 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux2,
           { "DDC 2 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux3,
           { "DDC 3 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux4,
           { "DDC 4 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux5,
           { "DDC 5 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux6,
           { "DDC 6 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddcc_ddc_mux7,
           { "DDC 7 Multiplexed", "openhpsdr-e.cr.ddcc.ddc-mux7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off),BOOLEAN_B7,
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
       { &hf_openhpsdr_e_hps_ptt,
           { "       PTT", "openhpsdr-e.hps.ptt",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive),BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_dot,
           { "       Dot", "openhpsdr-e.hps.dot",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive),BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_dash,
           { "      Dash", "openhpsdr-e.hps.dash",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_empty,
           { "     Empty", "openhpsdr-e.hps.empty",
             FT_BOOLEAN, BOOLEAN_MASK,
             NULL, BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_pll,
           { "       PLL", "openhpsdr-e.hps.pll",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&lock_unlock), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fifo_empty,
           { "FIFO Empty", "openhpsdr-e.hps.fifo-empty",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fifo_full,
           { "FIFO  Full", "openhpsdr-e.hps.fifo-full",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc0_ol,
           { "ADC 0 Overload", "openhpsdr-e.hps.adc0-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc1_ol,
           { "ADC 1 Overload", "openhpsdr-e.hps.adc1-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc2_ol,
           { "ADC 2 Overload", "openhpsdr-e.hps.adc2-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc3_ol,
           { "ADC 3 Overload", "openhpsdr-e.hps.adc3-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc4_ol,
           { "ADC 4 Overload", "openhpsdr-e.hps.adc4-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc5_ol,
           { "ADC 5 Overload", "openhpsdr-e.hps.adc5-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc6_ol,
           { "ADC 6 Overload", "openhpsdr-e.hps.adc6-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_adc7_ol,
           { "ADC 7 Overload", "openhpsdr-e.hps.adc7-ol",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_ex_power0,
           { "Exciter Power 0" , "openhpsdr-e.hps.ex-power0",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_ex_power1,
           { "Exciter Power 1" , "openhpsdr-e.hps.ex-power1",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_ex_power2,
           { "Exciter Power 2" , "openhpsdr-e.hps.ex-power2",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_ex_power3,
           { "Exciter Power 3" , "openhpsdr-e.hps.ex-power3",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fp_alex0,
           { "Forward Power -  Alex 0" , "openhpsdr-e.hps.fp-alex0",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fp_alex1,
           { "Forward Power -  Alex 1" , "openhpsdr-e.hps.fp-alex1",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fp_alex2,
           { "Forward Power -  Alex 2" , "openhpsdr-e.hps.fp-alex2",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_fp_alex3,
           { "Forward Power -  Alex 3" , "openhpsdr-e.hps.fp-alex3",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_rp_alex0,
           { "Reverse Power -  Alex 0" , "openhpsdr-e.hps.rp-alex0",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_rp_alex1,
           { "Reverse Power -  Alex 1" , "openhpsdr-e.hps.rp-alex1",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_rp_alex2,
           { "Reverse Power -  Alex 2" , "openhpsdr-e.hps.rp-alex2",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_rp_alex3,
           { "Reverse Power -  Alex 3" , "openhpsdr-e.hps.rp-alex3",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_supp_vol,
           { "Supply Voltage" , "openhpsdr-e.hps.supply-volt",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_adc3,
           { "User     ADC 3" , "openhpsdr-e.hps.user-adc3",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_adc2,
           { "User     ADC 2" , "openhpsdr-e.hps.user-adc2",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_adc1,
           { "User     ADC 1" , "openhpsdr-e.hps.user-adc1",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_adc0,
           { "User     ADC 0" , "openhpsdr-e.hps.user-adc0",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic0,
           { "User Logic 0", "openhpsdr-e.hps.user-logic0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic1,
           { "User Logic 1", "openhpsdr-e.hps.user-logic1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic2,
           { "User Logic 2", "openhpsdr-e.hps.user-logic2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic3,
           { "User Logic 3", "openhpsdr-e.hps.user-logic3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic4,
           { "User Logic 4", "openhpsdr-e.hps.user-logic4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic5,
           { "User Logic 5", "openhpsdr-e.hps.user-logic5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic6,
           { "User Logic 6", "openhpsdr-e.hps.user-logic6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hps_user_logic7,
           { "User Logic 7", "openhpsdr-e.hps.user-logic7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_set_notset), BOOLEAN_B7,
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
       { &hf_openhpsdr_e_ducc_dac_num,
           { "Harware number of DAC" , "openhpsdr-e.ducc.dac-num",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_eer,
           { "              EER", "openhpsdr-e.ducc.eer",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw,
           { "               CW", "openhpsdr-e.ducc.cw",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_rev_cw,
           { "       Reverse CW", "openhpsdr-e.ducc.rev-cw",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_iambic,
           { "           Iambic", "openhpsdr-e.ducc.iambic",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_sidetone,
           { "     CW Side Tone", "openhpsdr-e.ducc.sidetone",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_mode_b,
           { "        CW Mode B", "openhpsdr-e.ducc.cw-mode-b",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_st_char_space,
           { "CW Strict Spacing", "openhpsdr-e.ducc.cw-st-space",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_breakin,
           { "      CW Break In", "openhpsdr-e.ducc.cw-break-in",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_sidetone_level,
           { "CW Sidetone Level    " , "openhpsdr-e.ducc.cw-sidetone-level",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_sidetone_freq,
           { "CW Sidetone Frequency" , "openhpsdr-e.ducc.cw-sidetone-freq",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_keyer_speed,
           { "CW Keyer Speed       " , "openhpsdr-e.ducc.cw-keyer-speed",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_keyer_weight,
           { "CW Keyer Weight      " , "openhpsdr-e.ducc.cw-keyer-weight",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_cw_hang_delay,
           { "CW Hang Delay        " , "openhpsdr-e.ducc.cw-hang-delay",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_rf_delay,
           { "RF Delay             " , "openhpsdr-e.ducc.rf-delay",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_duc0_sample,
           { "DUC 0 Sample Rate    " , "openhpsdr-e.ducc.duc0-sample",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_duc0_bits,
           { "DUC 0 I&Q Sample Size" , "openhpsdr-e.ducc.duc0-bits",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_duc0_phase_shift,
           { "DUC 0 Sample Rate    " , "openhpsdr-e.ducc.duc0-phase-shift",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_line_in,
           { "  Line In", "openhpsdr-e.ducc.line-in",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_mic_boost,
           { "Mic Boost", "openhpsdr-e.ducc.mic-boost",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_on_off), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_orion_mic_ptt,
           { "       Orion Mic PTT", "openhpsdr-e.ducc.orion-mic-ptt",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_disabled_enabled), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_orion_mic_ring_tip,
           { "Orion Mic Tip & Ring", "openhpsdr-e.ducc.orion-mic-tip-ring",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&orion_tip_ring), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_orion_mic_bias,
           { "      Orion Mic Bias", "openhpsdr-e.ducc.sidetone",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_line_in_gain,
           { "Line IN Gain                  " , "openhpsdr-e.ducc.line-in-gain",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ducc_attn_adc0_duc0,
           { "ADC 0 Step Attenuator on DUC 0" , "openhpsdr-e.ducc.attn-adc0-duc0",
            FT_UINT8, BASE_DEC,
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
       { &hf_openhpsdr_e_micl_separator,
           { "MIC / Line Sample Separator" , "openhpsdr-e.micl.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_micl_sample_idx,
           { "Sample Index", "openhpsdr-e.micl.sample-idx",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_micl_sample,
           { "Mic / Line In Sample From Hardware", "openhpsdr-e.micl.sample",
            FT_UINT16, BASE_HEX,
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
       { &hf_openhpsdr_e_hpc_run,
           { "Run  ", "openhpsdr-e.hpc.run",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_disabled_enabled), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_ptt0,
           { "PPT 0", "openhpsdr-e.hpc.ptt0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_ptt1,
           { "PPT 1", "openhpsdr-e.hpc.ptt1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_ptt2,
           { "PPT 2", "openhpsdr-e.hpc.ptt2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_ptt3,
           { "PPT 3", "openhpsdr-e.hpc.ptt3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_cwx0,
           { "CW Mode", "openhpsdr-e.hpc.cwx0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&host_hardware), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_dot,
           { "CW Dot ", "openhpsdr-e.hpc.cw-dot",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_dash,
           { "CW Dash", "openhpsdr-e.hpc.cw-dash",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_active_inactive), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_cwx1,
           { "CWX1               " , "openhpsdr-e.hpc.cwx1",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_cwx2,
           { "CWX2               " , "openhpsdr-e.hpc.cwx2",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_cwx3,
           { "CWX3               " , "openhpsdr-e.hpc.cwx3",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },

       { &hf_openhpsdr_e_hpc_ddc_fp_sub,
           { "DDC  Frequency / Phase Word Submenu" , "openhpsdr-e.ddcc.sync-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc0,
           { "DDC  0 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc0",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc1,
           { "DDC  1 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc1",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc2,
           { "DDC  2 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc2",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc3,
           { "DDC  3 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc3",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc4,
           { "DDC  4 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc4",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc5,
           { "DDC  5 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc5",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc6,
           { "DDC  6 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc6",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc7,
           { "DDC  7 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc7",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc8,
           { "DDC  8 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc8",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc9,
           { "DDC  9 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc9",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc10,
           { "DDC 10 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc10",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc11,
           { "DDC 11 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc11",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc12,
           { "DDC 12 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc12",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc13,
           { "DDC 13 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc13",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc14,
           { "DDC 14 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc14",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc15,
           { "DDC 15 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc15",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc16,
           { "DDC 16 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc16",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc17,
           { "DDC 17 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc17",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc18,
           { "DDC 18 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc18",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc19,
           { "DDC 19 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc19",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc20,
           { "DDC 20 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc20",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc21,
           { "DDC 21 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc21",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc22,
           { "DDC 22 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc22",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc23,
           { "DDC 23 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc23",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc24,
           { "DDC 24 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc24",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc25,
           { "DDC 25 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc25",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc26,
           { "DDC 26 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc26",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc27,
           { "DDC 27 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc27",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc28,
           { "DDC 28 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc28",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc29,
           { "DDC 29 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc29",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc30,
           { "DDC 30 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc30",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc31,
           { "DDC 31 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc31",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc32,
           { "DDC 32 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc32",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc33,
           { "DDC 33 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc33",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc34,
           { "DDC 34 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc34",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc35,
           { "DDC 35 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc35",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc36,
           { "DDC 36 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc36",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc37,
           { "DDC 37 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc37",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc38,
           { "DDC 38 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc38",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc39,
           { "DDC 39 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc39",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc40,
           { "DDC 40 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc40",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc41,
           { "DDC 41 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc41",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc42,
           { "DDC 42 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc42",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc43,
           { "DDC 43 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc43",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc44,
           { "DDC 44 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc44",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc45,
           { "DDC 45 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc45",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc46,
           { "DDC 46 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc46",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc47,
           { "DDC 47 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc47",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc48,
           { "DDC 48 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc48",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc49,
           { "DDC 49 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc49",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc50,
           { "DDC 50 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc50",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc51,
           { "DDC 51 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc51",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc52,
           { "DDC 52 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc52",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc53,
           { "DDC 53 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc53",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc54,
           { "DDC 54 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc54",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc55,
           { "DDC 55 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc55",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc56,
           { "DDC 56 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc56",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc57,
           { "DDC 57 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc57",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc58,
           { "DDC 58 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc58",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc59,
           { "DDC 59 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc59",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc60,
           { "DDC 60 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc60",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc61,
           { "DDC 61 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc61",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc62,
           { "DDC 62 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc62",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc63,
           { "DDC 63 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc63",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc64,
           { "DDC 64 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc64",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc65,
           { "DDC 65 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc65",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc66,
           { "DDC 66 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc66",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc67,
           { "DDC 67 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc67",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc68,
           { "DDC 68 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc68",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc69,
           { "DDC 69 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc69",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc70,
           { "DDC 70 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc70",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc71,
           { "DDC 71 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc71",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc72,
           { "DDC 72 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc72",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc73,
           { "DDC 73 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc73",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc74,
           { "DDC 74 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc74",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc75,
           { "DDC 75 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc75",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc76,
           { "DDC 76 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc76",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc77,
           { "DDC 77 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc77",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc78,
           { "DDC 78 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc78",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_ddc79,
           { "DDC 79 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-ddc79",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_duc0,
           { "DUC 0 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-duc0",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_duc1,
           { "DUC 1 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-duc1",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_duc2,
           { "DUC 2 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-duc2",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_freq_phase_duc3,
           { "DUC 3 Frequency / Phase Word", "openhpsdr-e.hpc.freq-phase-duc3",
            FT_UINT32, BASE_DEC,
            NULL,ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_drive_duc0,
           { "DUC 0 Drive Level           " , "openhpsdr-e.hpc.duc0-drive",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_drive_duc1,
           { "DUC 1 Drive Level           " , "openhpsdr-e.hpc.duc1-drive",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_drive_duc2,
           { "DUC 2 Drive Level           " , "openhpsdr-e.hpc.duc2-drive",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_drive_duc3,
           { "DUC 3 Drive Level           " , "openhpsdr-e.hpc.duc3-drive",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col0,
           { "Open Collector Out 0", "openhpsdr-e.hpc.open-col0",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col1,
           { "Open Collector Out 1", "openhpsdr-e.hpc.open-col1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col2,
           { "Open Collector Out 2", "openhpsdr-e.hpc.open-col2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col3,
           { "Open Collector Out 3", "openhpsdr-e.hpc.open-col3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col4,
           { "Open Collector Out 4", "openhpsdr-e.hpc.open-col4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B4,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col5,
           { "Open Collector Out 5", "openhpsdr-e.hpc.open-col5",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B5,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col6,
           { "Open Collector Out 6", "openhpsdr-e.hpc.open-col6",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B6,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_open_col7,
           { "Open Collector Out 7", "openhpsdr-e.hpc.open-col7",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B7,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_db9_out1,
           { "Metis DB9 pin 1", "openhpsdr-e.hpc.db9-1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_db9_out2,
           { "Metis DB9 pin 2", "openhpsdr-e.hpc.db9-2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_db9_out3,
           { "Metis DB9 pin 3", "openhpsdr-e.hpc.db9-3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_db9_out4,
           { "Metis DB9 pin 4", "openhpsdr-e.hpc.db9-4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_merc_att1,
           { "Mercury 1 20dB Attenuate", "openhpsdr-e.hpc.merc_att1",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B0,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_merc_att2,
           { "Mercury 2 20dB Attenuate", "openhpsdr-e.hpc.merc_att2",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B1,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_merc_att3,
           { "Mercury 3 20dB Attenuate", "openhpsdr-e.hpc.merc_att3",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B2,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_merc_att4,
           { "Mercury 4 20dB Attenuate", "openhpsdr-e.hpc.merc_att4",
             FT_BOOLEAN, BOOLEAN_MASK,
             TFS(&local_enabled_disabled), BOOLEAN_B3,
             NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex7,
           { "Alex 7" , "openhpsdr-e.hpc.alex7",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex6,
           { "Alex 6" , "openhpsdr-e.hpc.alex6",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex5,
           { "Alex 5" , "openhpsdr-e.hpc.alex5",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex4,
           { "Alex 4" , "openhpsdr-e.hpc.alex4",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex3,
           { "Alex 3" , "openhpsdr-e.hpc.alex3",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex2,
           { "Alex 2" , "openhpsdr-e.hpc.alex2",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex1,
           { "Alex 1" , "openhpsdr-e.hpc.alex1",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_sub,
           { "Alex 0 Submenu" , "openhpsdr-e.ddcc.alex0-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },   
       { &hf_openhpsdr_e_hpc_alex0_lpf_17_15,
           { "Alex 0 - 17-15m LPF " , "openhpsdr-e.hpc.alex0-lpf_17-15",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_lpf_12_10,
           { "Alex 0 - 12-10m LPF " , "openhpsdr-e.hpc.alex0-lpf_12-10",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_bypass,
           { "Alex 0 - Bypass     " , "openhpsdr-e.hpc.alex0-bypass",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_red_led1,
           { "Alex 0 - Red LED 1  " , "openhpsdr-e.hpc.alex0-red_led1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_tx_rx,
           { "Alex 0 - TX / RX    " , "openhpsdr-e.hpc.alex0-tx_rx",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ant3,
           { "Alex 0 - Antenna 3  " , "openhpsdr-e.hpc.alex0-ant3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ant2,
           { "Alex 0 - Antenna 2  " , "openhpsdr-e.hpc.alex0-ant2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ant1,
           { "Alex 0 - Antenna 1  " , "openhpsdr-e.hpc.alex0-ant1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_lpf_160,
           { "Alex 0 - 160m LPF   " , "openhpsdr-e.hpc.alex0-lpf_160",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_lpf_80,
           { "Alex 0 - 80m LPF    " , "openhpsdr-e.hpc.alex0-lpf_80",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_lpf_60_40,
           { "Alex 0 - 60-40m LPF " , "openhpsdr-e.hpc.alex0-lpf_60-40",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_lpf_30_20,
           { "Alex 0 - 30-20m LPF " , "openhpsdr-e.hpc.alex0-lpf_30-20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_yel_led1,
           { "Alex 0 - Yellow LED1" , "openhpsdr-e.hpc.alex0-yel_led1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_red_led0,
           { "Alex 0 - Red LED 0  " , "openhpsdr-e.hpc.alex0-red_led0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B0,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_att_10,
           { "Alex 0 - Atten. 10dB" , "openhpsdr-e.hpc.alex0-att_10",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_att_20,
           { "Alex 0 - Atten. 20dB" , "openhpsdr-e.hpc.alex0-att_20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hf_bypass,
           { "Alex 0 - HF Bypass  " , "openhpsdr-e.hpc.alex0-hf-bypass",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ddc1_out,
           { "Alex 0 - DDC 1 Out  " , "openhpsdr-e.hpc.alex0-ddc1-out",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ddc1_in,
           { "Alex 0 - DDC 1 In   " , "openhpsdr-e.hpc.alex0-ddc1-in",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ddc2_in,
           { "Alex 0 - DDC 2 In   " , "openhpsdr-e.hpc.alex0-ddc2-in",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_ddc_xvtr_in,
           { "Alex 0 - DDC XVTR In" , "openhpsdr-e.hpc.alex0-ddc-xvtr-in",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hpf_1_5,
           { "Alex 0 - 1.5 MHZ HPF" , "openhpsdr-e.hpc.alex0-hpf_1-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B1,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hpf_6_5,
           { "Alex 0 - 6.5 MHZ HPF" , "openhpsdr-e.hpc.alex0-hpf_6-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B2,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hpf_9_5,
           { "Alex 0 - 9.5 MHZ HPF" , "openhpsdr-e.hpc.alex0-hpf_9-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B3,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_6m_amp,
           { "Alex 0 - 6M Amp     " , "openhpsdr-e.hpc.alex0-6m-amp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B4,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hpf_20,
           { "Alex 0 - 20 MHZ HPF " , "openhpsdr-e.hpc.alex0-hpf_20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B5,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_hpf_13,
           { "Alex 0 - 13 MHZ HPF " , "openhpsdr-e.hpc.alex0-hpf_13",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B6,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_alex0_yel_led0,
           { "Alex 0 - Yellow LED0" , "openhpsdr-e.hpc.alex0-yel_led0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), BOOLEAN_B7,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att7,
           { "Step Atten. 7" , "openhpsdr-e.hpc.att7",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att6,
           { "Step Atten. 6" , "openhpsdr-e.hpc.att6",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att5,
           { "Step Atten. 5" , "openhpsdr-e.hpc.att5",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att4,
           { "Step Atten. 4" , "openhpsdr-e.hpc.att4",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att3,
           { "Step Atten. 3" , "openhpsdr-e.hpc.att3",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att2,
           { "Step Atten. 2" , "openhpsdr-e.hpc.att2",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att1,
           { "Step Atten. 1" , "openhpsdr-e.hpc.att1",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_hpc_att0,
           { "Step Atten. 0" , "openhpsdr-e.hpc.att0",
            FT_UINT8, BASE_DEC,
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
       { &hf_openhpsdr_e_wbd_adc,
           { "Wide Band ADC" , "openhpsdr-e.wbd.adc",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_wbd_separator,
           { "Wide Band Data Sample Separator" , "openhpsdr-e.wbd.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_wbd_sample_idx,
           { "Sample Index", "openhpsdr-e.wbd.sample-idx",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_wbd_sample,
           { "Wide Band Sample From Hardware", "openhpsdr-e.wbd.sample",
            FT_UINT16, BASE_HEX,
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
       { &hf_openhpsdr_e_ddca_sample_bits,
           { "Bits Per Sample", "openhpsdr-e.ddca.sample-bits",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_ddca_separator,
           { "DDC Audio Data Sample Separator" , "openhpsdr-e.ddca.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddca_sample_idx,
           { "Sample Index", "openhpsdr-e.ddca.sample-idx",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_ddca_l_sample,
           { "DDC Left  Audio Sample From Host", "openhpsdr-e.ddca.sample-l",
            FT_UINT16, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddca_r_sample,
           { "DDC Right Audio Sample From Host", "openhpsdr-e.ddca.sample-r",
            FT_UINT16, BASE_HEX,
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
       { &hf_openhpsdr_e_duciq_duc,
           { "Duc Number" , "openhpsdr-e.wbd.duc",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_duciq_sample_bits,
           { "Bits Per Sample", "openhpsdr-e.duciq.sample-bits",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_duciq_separator,
           { "DUC I&Q Data Sample Separator" , "openhpsdr-e.duciq.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_duciq_sample_idx,
           { "Sample Index", "openhpsdr-e.duciq.sample-idx",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_duciq_i_sample,
           { "DUC I Sample From Host", "openhpsdr-e.duciq.sample-i",
            FT_UINT24, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_duciq_q_sample,
           { "DUC Q Sample From Host", "openhpsdr-e.duciq.sample-q",
            FT_UINT24, BASE_HEX,
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
           { "Sequence Number    ", "openhpsdr-e.ddciq.squence-num",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_time_stamp,
           { "Time Stamp         ", "openhpsdr-e.ddciq.time-stamp",
            FT_UINT64, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_ddciq_ddc,
           { "DDC Number         " , "openhpsdr-e.ddciq.ddc",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_sample_bits,
           { "Bits Per Sample    ", "openhpsdr-e.ddciq.sample-bits",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_samples_per_frame,
           { "Sample Per Frame   ", "openhpsdr-e.ddciq.sample-per-frame",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_ethernet_frame_size,
           { "Ethernet Frame Size", "openhpsdr-e.ddciq.ethernet-frame-size",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_separator,
           { "DDC I&Q Data Sample Separator" , "openhpsdr-e.ddciq.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_sample_idx,
           { "Sample Index", "openhpsdr-e.ddciq.sample-idx",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_ddciq_8b_i_sample,
           { "DDC I Sample From Hardware", "openhpsdr-e.ddciq.sample-i",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_8b_q_sample,
           { "DDC Q Sample From Hardware", "openhpsdr-e.ddciq.sample-q",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_16b_i_sample,
           { "DDC I Sample From Hardware", "openhpsdr-e.ddciq.sample-i",
            FT_UINT16, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_16b_q_sample,
           { "DDC Q Sample From Hardware", "openhpsdr-e.ddciq.sample-q",
            FT_UINT16, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_24b_i_sample,
           { "DDC I Sample From Hardware", "openhpsdr-e.ddciq.sample-i",
            FT_UINT24, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_24b_q_sample,
           { "DDC Q Sample From Hardware", "openhpsdr-e.ddciq.sample-q",
            FT_UINT24, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_32b_i_sample,
           { "DDC I Sample From Hardware", "openhpsdr-e.ddciq.sample-i",
            FT_UINT32, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_ddciq_32b_q_sample,
           { "DDC Q Sample From Hardware", "openhpsdr-e.ddciq.sample-q",
            FT_UINT32, BASE_HEX,
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
       { &hf_openhpsdr_e_mem_separator,
           { "Memory Mapped Separator" , "openhpsdr-e.ddciq.sep",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_openhpsdr_e_mem_idx,
           { "Address/Data Index", "openhpsdr-e.mem.idx",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_mem_address,
           { "Memory Address    ", "openhpsdr-e.mem.address",
            FT_UINT16, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_openhpsdr_e_mem_data,
           { "Memory Data       ", "openhpsdr-e.mem.data",
            FT_UINT16, BASE_HEX,
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
   
   prefs_register_bool_preference(openhpsdr_e_prefs,"ddciq_iq_mtu_check",
       "DDC I&Q Samples MTU Check (DDCIQ)",
       "Check to see if the number of I&Q Samples"
       " will exceed the maximum Ethernet MTU (1500 bytes)."
       " When disabled, there will be no checking"
       " to see if the MTU will be exceeded.",
       &openhpsdr_e_ddciq_mtu_check); 

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
   //guint8 board_id = -1;
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
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_proto_ver,tvb,offset,1,value,
       "openHPSDR Protocol: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_fw_ver,tvb,offset,1,value,
       "Firmware   Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc0_ver,tvb,offset,1,value,
       "Mercury0   Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc1_ver,tvb,offset,1,value,
       "Mercury1   Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc2_ver,tvb,offset,1,value,
       "Mercury2   Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_merc3_ver,tvb,offset,1,value,
       "Mercury3   Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_penny_ver,tvb,offset,1,value,
       "Penny      Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   value = tvb_get_guint8(tvb, offset);
   proto_tree_add_uint_format(tree,hf_openhpsdr_e_cr_disc_metis_ver,tvb,offset,1,value,
       "Metis      Version: %d.%.1d",(value/10),(value%10));
   offset += 1;

   proto_tree_add_item(tree,hf_openhpsdr_e_cr_disc_ddc_num,tvb,offset,1,ENC_BIG_ENDIAN);
   offset += 1;

   boolean_byte = tvb_get_guint8(tvb, offset);
   proto_tree_add_boolean(tree, hf_openhpsdr_e_cr_disc_freq_phase, tvb,offset, 1, boolean_byte);
   offset += 1;

   offset = cr_packet_end_pad(tvb,tree,offset,38);
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

   guint8 boolean_byte = -1;  //only need one of these
   guint8 value = -1;         // 

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
               /*
               // Detect service port change
               if ( openhpsdr_e_cr_ducc_port != ducc_current_port) {
                   ducc_current_port == openhpsdr_e_cr_ducc_port;
                   ddcc_initialized = FALSE;
               }
               */
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
               proto_tree_add_boolean(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_gen_wb_en_1, tvb,offset, 1,boolean_byte);               
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
               cr_check_length(tvb,pinfo,tree,offset);
               
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
               cr_check_length(tvb,pinfo,tree,offset); 

           } else if (pinfo->srcport == HPSDR_E_PORT_COM_REP) {

               // When Sequence Number equal 0 and bytes 14 to 59 are 0, the reply from the 
               // hardware is ether a Erase Acknowledgment or a Erase Complete. Byte 14 to 
               // vers 2.6 of protocol specification document is the byte after the 
               // "Firmware Code Verison". When bytes 14 to 21 are not zero, the reply 
               // from the hardware is a In Use Discovery Reply.

               //if (  tvb_get_guint32(tvb,offset-5,6) == 0  &&  tvb_get_guint64(tvb,offset-5,8) == 0 ) {
               if (  tvb_get_guint32(tvb,offset-5,6) == 0 && tvb_get_guint64(tvb,offset+10,8) == 0 ) {
                  proto_item_append_text(append_text_item," :Erase - Acknowledgment or Complete");

                  discovery_ether_mac = tvb_get_ptr(tvb, 5, 6); // Has to be defined before using. 


                  proto_tree_add_ether(openhpsdr_e_cr_tree, hf_openhpsdr_e_cr_disc_mac, tvb,offset, 6, discovery_ether_mac);
                  offset += 6;

                  proto_tree_add_item(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_disc_board,tvb,offset,1,ENC_BIG_ENDIAN);
                  offset += 1;

                  value = tvb_get_guint8(tvb, offset);
                  proto_tree_add_uint_format(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_disc_proto_ver,tvb,offset,1,value,
                      "openHPSDR Protocol: %d.%.1d",(value/10),(value%10));
                  offset += 1;   

                 value = tvb_get_guint8(tvb, offset);
                 proto_tree_add_uint_format(openhpsdr_e_cr_tree,hf_openhpsdr_e_cr_disc_fw_ver,tvb,offset,1,value,
                     "Firmware   Version: %d.%.1d",(value/10),(value%10));
                 offset += 1;

                 offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,46);
                 cr_check_length(tvb,pinfo,tree,offset);
      

               } else {           
                   proto_item_append_text(append_text_item," :Discovery - Hardware Discovery Reply (Hardware In Use)");
                   cr_discovery_reply(tvb,pinfo,openhpsdr_e_cr_tree,offset);
               } 

           } 

       } else if (cr_command == 0x04) { // 0x04 Erase - Program Data Request
           if (pinfo->destport == HPSDR_E_PORT_COM_REP) {
               proto_item_append_text(append_text_item," :Erase - Host Erase Command");

               offset = cr_packet_end_pad(tvb,openhpsdr_e_cr_tree,offset,55);
               cr_check_length(tvb,pinfo,tree,offset);

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

               cr_check_length(tvb,pinfo,tree,offset);
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
   guint8 value = -1;

   int i = -1;

   int *array0[80];
   int *array1[80];
   int *array2[80];
   int *array3[80];
   int *array4[80];
   int *array5[80];
   int *array6[80];
   int *array7[80];

   const char *placehold = NULL ;  

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DDCC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {

       proto_item *parent_tree_ddcc_item = NULL;
       proto_item *ditram_tree_ddcc_item = NULL;
       proto_item *state_tree_ddcc_item = NULL;
       proto_item *config_tree_ddcc_item = NULL;
       proto_item *sync_tree_ddcc_item = NULL; 
       proto_item *mux_tree_ddcc_item = NULL; 

       proto_tree *openhpsdr_e_ddcc_tree = NULL;
       proto_tree *openhpsdr_e_ddcc_ditram_tree = NULL;
       proto_tree *openhpsdr_e_ddcc_state_tree = NULL;
       proto_tree *openhpsdr_e_ddcc_config_tree = NULL;
       proto_tree *openhpsdr_e_ddcc_sync_tree = NULL;
       proto_tree *openhpsdr_e_ddcc_mux_tree = NULL;

       proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ddcc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ddcc_tree = proto_item_add_subtree(parent_tree_ddcc_item, ett_openhpsdr_e_ddcc);

       proto_tree_add_string_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DDC Command");       

       proto_tree_add_item(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       proto_tree_add_item(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_adc_num, tvb,offset, 1, ENC_BIG_ENDIAN); 
       offset += 1;

       ditram_tree_ddcc_item = proto_tree_add_uint_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_ditram_sub, 
           tvb, offset,2, value,"ADC Dither and Random"); 
       openhpsdr_e_ddcc_ditram_tree = proto_item_add_subtree(ditram_tree_ddcc_item,ett_openhpsdr_e_ddcc_ditram);
       
       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither1, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither2, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither3, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither4, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither5, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither6, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_dither7, tvb,offset, 1, value); 
       offset += 1; 

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random1, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random2, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random3, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random4, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random5, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random6, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_ditram_tree, hf_openhpsdr_e_ddcc_adc_random7, tvb,offset, 1, value); 
       offset += 1;

       state_tree_ddcc_item = proto_tree_add_uint_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_state_sub, 
           tvb, offset,10, value,"DDC State"); 
       openhpsdr_e_ddcc_state_tree = proto_item_add_subtree(state_tree_ddcc_item,ett_openhpsdr_e_ddcc_state);

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc4, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc6, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc7, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc8, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc9, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc10, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc11, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc12, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc13, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc14, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc15, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc16, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc17, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc18, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc19, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc20, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc21, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc22, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc23, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc24, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc25, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc26, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc27, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc28, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc29, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc30, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc31, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc32, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc33, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc34, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc35, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc36, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc37, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc38, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc39, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc40, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc41, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc42, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc43, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc44, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc45, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc46, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc47, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc48, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc49, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc50, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc51, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc52, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc53, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc54, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc55, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc56, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc57, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc58, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc59, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc60, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc61, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc62, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc63, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc64, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc65, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc66, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc67, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc68, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc69, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc70, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc71, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc72, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc73, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc74, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc75, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc76, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc77, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc78, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_state_tree, hf_openhpsdr_e_ddcc_ddc79, tvb,offset, 1, value);
       offset += 1;


       array0[0] = &hf_openhpsdr_e_ddcc_ddc_asign0;
       array1[0] = &hf_openhpsdr_e_ddcc_ddc_rate0;
       array2[0] = &hf_openhpsdr_e_ddcc_ddc_cic1_0;
       array3[0] = &hf_openhpsdr_e_ddcc_ddc_cic2_0;
       array4[0] = &hf_openhpsdr_e_ddcc_ddc_size0;
       array0[1] = &hf_openhpsdr_e_ddcc_ddc_asign1;
       array1[1] = &hf_openhpsdr_e_ddcc_ddc_rate1;
       array2[1] = &hf_openhpsdr_e_ddcc_ddc_cic1_1;
       array3[1] = &hf_openhpsdr_e_ddcc_ddc_cic2_1;
       array4[1] = &hf_openhpsdr_e_ddcc_ddc_size1;
       array0[2] = &hf_openhpsdr_e_ddcc_ddc_asign2;
       array1[2] = &hf_openhpsdr_e_ddcc_ddc_rate2;
       array2[2] = &hf_openhpsdr_e_ddcc_ddc_cic1_2;
       array3[2] = &hf_openhpsdr_e_ddcc_ddc_cic2_2;
       array4[2] = &hf_openhpsdr_e_ddcc_ddc_size2;
       array0[3] = &hf_openhpsdr_e_ddcc_ddc_asign3;
       array1[3] = &hf_openhpsdr_e_ddcc_ddc_rate3;
       array2[3] = &hf_openhpsdr_e_ddcc_ddc_cic1_3;
       array3[3] = &hf_openhpsdr_e_ddcc_ddc_cic2_3;
       array4[3] = &hf_openhpsdr_e_ddcc_ddc_size3;
       array0[4] = &hf_openhpsdr_e_ddcc_ddc_asign4;
       array1[4] = &hf_openhpsdr_e_ddcc_ddc_rate4;
       array2[4] = &hf_openhpsdr_e_ddcc_ddc_cic1_4;
       array3[4] = &hf_openhpsdr_e_ddcc_ddc_cic2_4;
       array4[4] = &hf_openhpsdr_e_ddcc_ddc_size4;
       array0[5] = &hf_openhpsdr_e_ddcc_ddc_asign5;
       array1[5] = &hf_openhpsdr_e_ddcc_ddc_rate5;
       array2[5] = &hf_openhpsdr_e_ddcc_ddc_cic1_5;
       array3[5] = &hf_openhpsdr_e_ddcc_ddc_cic2_5;
       array4[5] = &hf_openhpsdr_e_ddcc_ddc_size5;
       array0[6] = &hf_openhpsdr_e_ddcc_ddc_asign6;
       array1[6] = &hf_openhpsdr_e_ddcc_ddc_rate6;
       array2[6] = &hf_openhpsdr_e_ddcc_ddc_cic1_6;
       array3[6] = &hf_openhpsdr_e_ddcc_ddc_cic2_6;
       array4[6] = &hf_openhpsdr_e_ddcc_ddc_size6;
       array0[7] = &hf_openhpsdr_e_ddcc_ddc_asign7;
       array1[7] = &hf_openhpsdr_e_ddcc_ddc_rate7;
       array2[7] = &hf_openhpsdr_e_ddcc_ddc_cic1_7;
       array3[7] = &hf_openhpsdr_e_ddcc_ddc_cic2_7;
       array4[7] = &hf_openhpsdr_e_ddcc_ddc_size7;
       array0[8] = &hf_openhpsdr_e_ddcc_ddc_asign8;
       array1[8] = &hf_openhpsdr_e_ddcc_ddc_rate8;
       array2[8] = &hf_openhpsdr_e_ddcc_ddc_cic1_8;
       array3[8] = &hf_openhpsdr_e_ddcc_ddc_cic2_8;
       array4[8] = &hf_openhpsdr_e_ddcc_ddc_size8;
       array0[9] = &hf_openhpsdr_e_ddcc_ddc_asign9;
       array1[9] = &hf_openhpsdr_e_ddcc_ddc_rate9;
       array2[9] = &hf_openhpsdr_e_ddcc_ddc_cic1_9;
       array3[9] = &hf_openhpsdr_e_ddcc_ddc_cic2_9;
       array4[9] = &hf_openhpsdr_e_ddcc_ddc_size9;
       array0[10] = &hf_openhpsdr_e_ddcc_ddc_asign10;
       array1[10] = &hf_openhpsdr_e_ddcc_ddc_rate10;
       array2[10] = &hf_openhpsdr_e_ddcc_ddc_cic1_10;
       array3[10] = &hf_openhpsdr_e_ddcc_ddc_cic2_10;
       array4[10] = &hf_openhpsdr_e_ddcc_ddc_size10;
       array0[11] = &hf_openhpsdr_e_ddcc_ddc_asign11;
       array1[11] = &hf_openhpsdr_e_ddcc_ddc_rate11;
       array2[11] = &hf_openhpsdr_e_ddcc_ddc_cic1_11;
       array3[11] = &hf_openhpsdr_e_ddcc_ddc_cic2_11;
       array4[11] = &hf_openhpsdr_e_ddcc_ddc_size11;
       array0[12] = &hf_openhpsdr_e_ddcc_ddc_asign12;
       array1[12] = &hf_openhpsdr_e_ddcc_ddc_rate12;
       array2[12] = &hf_openhpsdr_e_ddcc_ddc_cic1_12;
       array3[12] = &hf_openhpsdr_e_ddcc_ddc_cic2_12;
       array4[12] = &hf_openhpsdr_e_ddcc_ddc_size12;
       array0[13] = &hf_openhpsdr_e_ddcc_ddc_asign13;
       array1[13] = &hf_openhpsdr_e_ddcc_ddc_rate13;
       array2[13] = &hf_openhpsdr_e_ddcc_ddc_cic1_13;
       array3[13] = &hf_openhpsdr_e_ddcc_ddc_cic2_13;
       array4[13] = &hf_openhpsdr_e_ddcc_ddc_size13;
       array0[14] = &hf_openhpsdr_e_ddcc_ddc_asign14;
       array1[14] = &hf_openhpsdr_e_ddcc_ddc_rate14;
       array2[14] = &hf_openhpsdr_e_ddcc_ddc_cic1_14;
       array3[14] = &hf_openhpsdr_e_ddcc_ddc_cic2_14;
       array4[14] = &hf_openhpsdr_e_ddcc_ddc_size14;
       array0[15] = &hf_openhpsdr_e_ddcc_ddc_asign15;
       array1[15] = &hf_openhpsdr_e_ddcc_ddc_rate15;
       array2[15] = &hf_openhpsdr_e_ddcc_ddc_cic1_15;
       array3[15] = &hf_openhpsdr_e_ddcc_ddc_cic2_15;
       array4[15] = &hf_openhpsdr_e_ddcc_ddc_size15;
       array0[16] = &hf_openhpsdr_e_ddcc_ddc_asign16;
       array1[16] = &hf_openhpsdr_e_ddcc_ddc_rate16;
       array2[16] = &hf_openhpsdr_e_ddcc_ddc_cic1_16;
       array3[16] = &hf_openhpsdr_e_ddcc_ddc_cic2_16;
       array4[16] = &hf_openhpsdr_e_ddcc_ddc_size16;
       array0[17] = &hf_openhpsdr_e_ddcc_ddc_asign17;
       array1[17] = &hf_openhpsdr_e_ddcc_ddc_rate17;
       array2[17] = &hf_openhpsdr_e_ddcc_ddc_cic1_17;
       array3[17] = &hf_openhpsdr_e_ddcc_ddc_cic2_17;
       array4[17] = &hf_openhpsdr_e_ddcc_ddc_size17;
       array0[18] = &hf_openhpsdr_e_ddcc_ddc_asign18;
       array1[18] = &hf_openhpsdr_e_ddcc_ddc_rate18;
       array2[18] = &hf_openhpsdr_e_ddcc_ddc_cic1_18;
       array3[18] = &hf_openhpsdr_e_ddcc_ddc_cic2_18;
       array4[18] = &hf_openhpsdr_e_ddcc_ddc_size18;
       array0[19] = &hf_openhpsdr_e_ddcc_ddc_asign19;
       array1[19] = &hf_openhpsdr_e_ddcc_ddc_rate19;
       array2[19] = &hf_openhpsdr_e_ddcc_ddc_cic1_19;
       array3[19] = &hf_openhpsdr_e_ddcc_ddc_cic2_19;
       array4[19] = &hf_openhpsdr_e_ddcc_ddc_size19;
       array0[20] = &hf_openhpsdr_e_ddcc_ddc_asign20;
       array1[20] = &hf_openhpsdr_e_ddcc_ddc_rate20;
       array2[20] = &hf_openhpsdr_e_ddcc_ddc_cic1_20;
       array3[20] = &hf_openhpsdr_e_ddcc_ddc_cic2_20;
       array4[20] = &hf_openhpsdr_e_ddcc_ddc_size20;
       array0[21] = &hf_openhpsdr_e_ddcc_ddc_asign21;
       array1[21] = &hf_openhpsdr_e_ddcc_ddc_rate21;
       array2[21] = &hf_openhpsdr_e_ddcc_ddc_cic1_21;
       array3[21] = &hf_openhpsdr_e_ddcc_ddc_cic2_21;
       array4[21] = &hf_openhpsdr_e_ddcc_ddc_size21;
       array0[22] = &hf_openhpsdr_e_ddcc_ddc_asign22;
       array1[22] = &hf_openhpsdr_e_ddcc_ddc_rate22;
       array2[22] = &hf_openhpsdr_e_ddcc_ddc_cic1_22;
       array3[22] = &hf_openhpsdr_e_ddcc_ddc_cic2_22;
       array4[22] = &hf_openhpsdr_e_ddcc_ddc_size22;
       array0[23] = &hf_openhpsdr_e_ddcc_ddc_asign23;
       array1[23] = &hf_openhpsdr_e_ddcc_ddc_rate23;
       array2[23] = &hf_openhpsdr_e_ddcc_ddc_cic1_23;
       array3[23] = &hf_openhpsdr_e_ddcc_ddc_cic2_23;
       array4[23] = &hf_openhpsdr_e_ddcc_ddc_size23;
       array0[24] = &hf_openhpsdr_e_ddcc_ddc_asign24;
       array1[24] = &hf_openhpsdr_e_ddcc_ddc_rate24;
       array2[24] = &hf_openhpsdr_e_ddcc_ddc_cic1_24;
       array3[24] = &hf_openhpsdr_e_ddcc_ddc_cic2_24;
       array4[24] = &hf_openhpsdr_e_ddcc_ddc_size24;
       array0[25] = &hf_openhpsdr_e_ddcc_ddc_asign25;
       array1[25] = &hf_openhpsdr_e_ddcc_ddc_rate25;
       array2[25] = &hf_openhpsdr_e_ddcc_ddc_cic1_25;
       array3[25] = &hf_openhpsdr_e_ddcc_ddc_cic2_25;
       array4[25] = &hf_openhpsdr_e_ddcc_ddc_size25;
       array0[26] = &hf_openhpsdr_e_ddcc_ddc_asign26;
       array1[26] = &hf_openhpsdr_e_ddcc_ddc_rate26;
       array2[26] = &hf_openhpsdr_e_ddcc_ddc_cic1_26;
       array3[26] = &hf_openhpsdr_e_ddcc_ddc_cic2_26;
       array4[26] = &hf_openhpsdr_e_ddcc_ddc_size26;
       array0[27] = &hf_openhpsdr_e_ddcc_ddc_asign27;
       array1[27] = &hf_openhpsdr_e_ddcc_ddc_rate27;
       array2[27] = &hf_openhpsdr_e_ddcc_ddc_cic1_27;
       array3[27] = &hf_openhpsdr_e_ddcc_ddc_cic2_27;
       array4[27] = &hf_openhpsdr_e_ddcc_ddc_size27;
       array0[28] = &hf_openhpsdr_e_ddcc_ddc_asign28;
       array1[28] = &hf_openhpsdr_e_ddcc_ddc_rate28;
       array2[28] = &hf_openhpsdr_e_ddcc_ddc_cic1_28;
       array3[28] = &hf_openhpsdr_e_ddcc_ddc_cic2_28;
       array4[28] = &hf_openhpsdr_e_ddcc_ddc_size28;
       array0[29] = &hf_openhpsdr_e_ddcc_ddc_asign29;
       array1[29] = &hf_openhpsdr_e_ddcc_ddc_rate29;
       array2[29] = &hf_openhpsdr_e_ddcc_ddc_cic1_29;
       array3[29] = &hf_openhpsdr_e_ddcc_ddc_cic2_29;
       array4[29] = &hf_openhpsdr_e_ddcc_ddc_size29;
       array0[30] = &hf_openhpsdr_e_ddcc_ddc_asign30;
       array1[30] = &hf_openhpsdr_e_ddcc_ddc_rate30;
       array2[30] = &hf_openhpsdr_e_ddcc_ddc_cic1_30;
       array3[30] = &hf_openhpsdr_e_ddcc_ddc_cic2_30;
       array4[30] = &hf_openhpsdr_e_ddcc_ddc_size30;
       array0[31] = &hf_openhpsdr_e_ddcc_ddc_asign31;
       array1[31] = &hf_openhpsdr_e_ddcc_ddc_rate31;
       array2[31] = &hf_openhpsdr_e_ddcc_ddc_cic1_31;
       array3[31] = &hf_openhpsdr_e_ddcc_ddc_cic2_31;
       array4[31] = &hf_openhpsdr_e_ddcc_ddc_size31;
       array0[32] = &hf_openhpsdr_e_ddcc_ddc_asign32;
       array1[32] = &hf_openhpsdr_e_ddcc_ddc_rate32;
       array2[32] = &hf_openhpsdr_e_ddcc_ddc_cic1_32;
       array3[32] = &hf_openhpsdr_e_ddcc_ddc_cic2_32;
       array4[32] = &hf_openhpsdr_e_ddcc_ddc_size32;
       array0[33] = &hf_openhpsdr_e_ddcc_ddc_asign33;
       array1[33] = &hf_openhpsdr_e_ddcc_ddc_rate33;
       array2[33] = &hf_openhpsdr_e_ddcc_ddc_cic1_33;
       array3[33] = &hf_openhpsdr_e_ddcc_ddc_cic2_33;
       array4[33] = &hf_openhpsdr_e_ddcc_ddc_size33;
       array0[34] = &hf_openhpsdr_e_ddcc_ddc_asign34;
       array1[34] = &hf_openhpsdr_e_ddcc_ddc_rate34;
       array2[34] = &hf_openhpsdr_e_ddcc_ddc_cic1_34;
       array3[34] = &hf_openhpsdr_e_ddcc_ddc_cic2_34;
       array4[34] = &hf_openhpsdr_e_ddcc_ddc_size34;
       array0[35] = &hf_openhpsdr_e_ddcc_ddc_asign35;
       array1[35] = &hf_openhpsdr_e_ddcc_ddc_rate35;
       array2[35] = &hf_openhpsdr_e_ddcc_ddc_cic1_35;
       array3[35] = &hf_openhpsdr_e_ddcc_ddc_cic2_35;
       array4[35] = &hf_openhpsdr_e_ddcc_ddc_size35;
       array0[36] = &hf_openhpsdr_e_ddcc_ddc_asign36;
       array1[36] = &hf_openhpsdr_e_ddcc_ddc_rate36;
       array2[36] = &hf_openhpsdr_e_ddcc_ddc_cic1_36;
       array3[36] = &hf_openhpsdr_e_ddcc_ddc_cic2_36;
       array4[36] = &hf_openhpsdr_e_ddcc_ddc_size36;
       array0[37] = &hf_openhpsdr_e_ddcc_ddc_asign37;
       array1[37] = &hf_openhpsdr_e_ddcc_ddc_rate37;
       array2[37] = &hf_openhpsdr_e_ddcc_ddc_cic1_37;
       array3[37] = &hf_openhpsdr_e_ddcc_ddc_cic2_37;
       array4[37] = &hf_openhpsdr_e_ddcc_ddc_size37;
       array0[38] = &hf_openhpsdr_e_ddcc_ddc_asign38;
       array1[38] = &hf_openhpsdr_e_ddcc_ddc_rate38;
       array2[38] = &hf_openhpsdr_e_ddcc_ddc_cic1_38;
       array3[38] = &hf_openhpsdr_e_ddcc_ddc_cic2_38;
       array4[38] = &hf_openhpsdr_e_ddcc_ddc_size38;
       array0[39] = &hf_openhpsdr_e_ddcc_ddc_asign39;
       array1[39] = &hf_openhpsdr_e_ddcc_ddc_rate39;
       array2[39] = &hf_openhpsdr_e_ddcc_ddc_cic1_39;
       array3[39] = &hf_openhpsdr_e_ddcc_ddc_cic2_39;
       array4[39] = &hf_openhpsdr_e_ddcc_ddc_size39;
       array0[40] = &hf_openhpsdr_e_ddcc_ddc_asign40;
       array1[40] = &hf_openhpsdr_e_ddcc_ddc_rate40;
       array2[40] = &hf_openhpsdr_e_ddcc_ddc_cic1_40;
       array3[40] = &hf_openhpsdr_e_ddcc_ddc_cic2_40;
       array4[40] = &hf_openhpsdr_e_ddcc_ddc_size40;
       array0[41] = &hf_openhpsdr_e_ddcc_ddc_asign41;
       array1[41] = &hf_openhpsdr_e_ddcc_ddc_rate41;
       array2[41] = &hf_openhpsdr_e_ddcc_ddc_cic1_41;
       array3[41] = &hf_openhpsdr_e_ddcc_ddc_cic2_41;
       array4[41] = &hf_openhpsdr_e_ddcc_ddc_size41;
       array0[42] = &hf_openhpsdr_e_ddcc_ddc_asign42;
       array1[42] = &hf_openhpsdr_e_ddcc_ddc_rate42;
       array2[42] = &hf_openhpsdr_e_ddcc_ddc_cic1_42;
       array3[42] = &hf_openhpsdr_e_ddcc_ddc_cic2_42;
       array4[42] = &hf_openhpsdr_e_ddcc_ddc_size42;
       array0[43] = &hf_openhpsdr_e_ddcc_ddc_asign43;
       array1[43] = &hf_openhpsdr_e_ddcc_ddc_rate43;
       array2[43] = &hf_openhpsdr_e_ddcc_ddc_cic1_43;
       array3[43] = &hf_openhpsdr_e_ddcc_ddc_cic2_43;
       array4[43] = &hf_openhpsdr_e_ddcc_ddc_size43;
       array0[44] = &hf_openhpsdr_e_ddcc_ddc_asign44;
       array1[44] = &hf_openhpsdr_e_ddcc_ddc_rate44;
       array2[44] = &hf_openhpsdr_e_ddcc_ddc_cic1_44;
       array3[44] = &hf_openhpsdr_e_ddcc_ddc_cic2_44;
       array4[44] = &hf_openhpsdr_e_ddcc_ddc_size44;
       array0[45] = &hf_openhpsdr_e_ddcc_ddc_asign45;
       array1[45] = &hf_openhpsdr_e_ddcc_ddc_rate45;
       array2[45] = &hf_openhpsdr_e_ddcc_ddc_cic1_45;
       array3[45] = &hf_openhpsdr_e_ddcc_ddc_cic2_45;
       array4[45] = &hf_openhpsdr_e_ddcc_ddc_size45;
       array0[46] = &hf_openhpsdr_e_ddcc_ddc_asign46;
       array1[46] = &hf_openhpsdr_e_ddcc_ddc_rate46;
       array2[46] = &hf_openhpsdr_e_ddcc_ddc_cic1_46;
       array3[46] = &hf_openhpsdr_e_ddcc_ddc_cic2_46;
       array4[46] = &hf_openhpsdr_e_ddcc_ddc_size46;
       array0[47] = &hf_openhpsdr_e_ddcc_ddc_asign47;
       array1[47] = &hf_openhpsdr_e_ddcc_ddc_rate47;
       array2[47] = &hf_openhpsdr_e_ddcc_ddc_cic1_47;
       array3[47] = &hf_openhpsdr_e_ddcc_ddc_cic2_47;
       array4[47] = &hf_openhpsdr_e_ddcc_ddc_size47;
       array0[48] = &hf_openhpsdr_e_ddcc_ddc_asign48;
       array1[48] = &hf_openhpsdr_e_ddcc_ddc_rate48;
       array2[48] = &hf_openhpsdr_e_ddcc_ddc_cic1_48;
       array3[48] = &hf_openhpsdr_e_ddcc_ddc_cic2_48;
       array4[48] = &hf_openhpsdr_e_ddcc_ddc_size48;
       array0[49] = &hf_openhpsdr_e_ddcc_ddc_asign49;
       array1[49] = &hf_openhpsdr_e_ddcc_ddc_rate49;
       array2[49] = &hf_openhpsdr_e_ddcc_ddc_cic1_49;
       array3[49] = &hf_openhpsdr_e_ddcc_ddc_cic2_49;
       array4[49] = &hf_openhpsdr_e_ddcc_ddc_size49;
       array0[50] = &hf_openhpsdr_e_ddcc_ddc_asign50;
       array1[50] = &hf_openhpsdr_e_ddcc_ddc_rate50;
       array2[50] = &hf_openhpsdr_e_ddcc_ddc_cic1_50;
       array3[50] = &hf_openhpsdr_e_ddcc_ddc_cic2_50;
       array4[50] = &hf_openhpsdr_e_ddcc_ddc_size50;
       array0[51] = &hf_openhpsdr_e_ddcc_ddc_asign51;
       array1[51] = &hf_openhpsdr_e_ddcc_ddc_rate51;
       array2[51] = &hf_openhpsdr_e_ddcc_ddc_cic1_51;
       array3[51] = &hf_openhpsdr_e_ddcc_ddc_cic2_51;
       array4[51] = &hf_openhpsdr_e_ddcc_ddc_size51;
       array0[52] = &hf_openhpsdr_e_ddcc_ddc_asign52;
       array1[52] = &hf_openhpsdr_e_ddcc_ddc_rate52;
       array2[52] = &hf_openhpsdr_e_ddcc_ddc_cic1_52;
       array3[52] = &hf_openhpsdr_e_ddcc_ddc_cic2_52;
       array4[52] = &hf_openhpsdr_e_ddcc_ddc_size52;
       array0[53] = &hf_openhpsdr_e_ddcc_ddc_asign53;
       array1[53] = &hf_openhpsdr_e_ddcc_ddc_rate53;
       array2[53] = &hf_openhpsdr_e_ddcc_ddc_cic1_53;
       array3[53] = &hf_openhpsdr_e_ddcc_ddc_cic2_53;
       array4[53] = &hf_openhpsdr_e_ddcc_ddc_size53;
       array0[54] = &hf_openhpsdr_e_ddcc_ddc_asign54;
       array1[54] = &hf_openhpsdr_e_ddcc_ddc_rate54;
       array2[54] = &hf_openhpsdr_e_ddcc_ddc_cic1_54;
       array3[54] = &hf_openhpsdr_e_ddcc_ddc_cic2_54;
       array4[54] = &hf_openhpsdr_e_ddcc_ddc_size54;
       array0[55] = &hf_openhpsdr_e_ddcc_ddc_asign55;
       array1[55] = &hf_openhpsdr_e_ddcc_ddc_rate55;
       array2[55] = &hf_openhpsdr_e_ddcc_ddc_cic1_55;
       array3[55] = &hf_openhpsdr_e_ddcc_ddc_cic2_55;
       array4[55] = &hf_openhpsdr_e_ddcc_ddc_size55;
       array0[56] = &hf_openhpsdr_e_ddcc_ddc_asign56;
       array1[56] = &hf_openhpsdr_e_ddcc_ddc_rate56;
       array2[56] = &hf_openhpsdr_e_ddcc_ddc_cic1_56;
       array3[56] = &hf_openhpsdr_e_ddcc_ddc_cic2_56;
       array4[56] = &hf_openhpsdr_e_ddcc_ddc_size56;
       array0[57] = &hf_openhpsdr_e_ddcc_ddc_asign57;
       array1[57] = &hf_openhpsdr_e_ddcc_ddc_rate57;
       array2[57] = &hf_openhpsdr_e_ddcc_ddc_cic1_57;
       array3[57] = &hf_openhpsdr_e_ddcc_ddc_cic2_57;
       array4[57] = &hf_openhpsdr_e_ddcc_ddc_size57;
       array0[58] = &hf_openhpsdr_e_ddcc_ddc_asign58;
       array1[58] = &hf_openhpsdr_e_ddcc_ddc_rate58;
       array2[58] = &hf_openhpsdr_e_ddcc_ddc_cic1_58;
       array3[58] = &hf_openhpsdr_e_ddcc_ddc_cic2_58;
       array4[58] = &hf_openhpsdr_e_ddcc_ddc_size58;
       array0[59] = &hf_openhpsdr_e_ddcc_ddc_asign59;
       array1[59] = &hf_openhpsdr_e_ddcc_ddc_rate59;
       array2[59] = &hf_openhpsdr_e_ddcc_ddc_cic1_59;
       array3[59] = &hf_openhpsdr_e_ddcc_ddc_cic2_59;
       array4[59] = &hf_openhpsdr_e_ddcc_ddc_size59;
       array0[60] = &hf_openhpsdr_e_ddcc_ddc_asign60;
       array1[60] = &hf_openhpsdr_e_ddcc_ddc_rate60;
       array2[60] = &hf_openhpsdr_e_ddcc_ddc_cic1_60;
       array3[60] = &hf_openhpsdr_e_ddcc_ddc_cic2_60;
       array4[60] = &hf_openhpsdr_e_ddcc_ddc_size60;
       array0[61] = &hf_openhpsdr_e_ddcc_ddc_asign61;
       array1[61] = &hf_openhpsdr_e_ddcc_ddc_rate61;
       array2[61] = &hf_openhpsdr_e_ddcc_ddc_cic1_61;
       array3[61] = &hf_openhpsdr_e_ddcc_ddc_cic2_61;
       array4[61] = &hf_openhpsdr_e_ddcc_ddc_size61;
       array0[62] = &hf_openhpsdr_e_ddcc_ddc_asign62;
       array1[62] = &hf_openhpsdr_e_ddcc_ddc_rate62;
       array2[62] = &hf_openhpsdr_e_ddcc_ddc_cic1_62;
       array3[62] = &hf_openhpsdr_e_ddcc_ddc_cic2_62;
       array4[62] = &hf_openhpsdr_e_ddcc_ddc_size62;
       array0[63] = &hf_openhpsdr_e_ddcc_ddc_asign63;
       array1[63] = &hf_openhpsdr_e_ddcc_ddc_rate63;
       array2[63] = &hf_openhpsdr_e_ddcc_ddc_cic1_63;
       array3[63] = &hf_openhpsdr_e_ddcc_ddc_cic2_63;
       array4[63] = &hf_openhpsdr_e_ddcc_ddc_size63;
       array0[64] = &hf_openhpsdr_e_ddcc_ddc_asign64;
       array1[64] = &hf_openhpsdr_e_ddcc_ddc_rate64;
       array2[64] = &hf_openhpsdr_e_ddcc_ddc_cic1_64;
       array3[64] = &hf_openhpsdr_e_ddcc_ddc_cic2_64;
       array4[64] = &hf_openhpsdr_e_ddcc_ddc_size64;
       array0[65] = &hf_openhpsdr_e_ddcc_ddc_asign65;
       array1[65] = &hf_openhpsdr_e_ddcc_ddc_rate65;
       array2[65] = &hf_openhpsdr_e_ddcc_ddc_cic1_65;
       array3[65] = &hf_openhpsdr_e_ddcc_ddc_cic2_65;
       array4[65] = &hf_openhpsdr_e_ddcc_ddc_size65;
       array0[66] = &hf_openhpsdr_e_ddcc_ddc_asign66;
       array1[66] = &hf_openhpsdr_e_ddcc_ddc_rate66;
       array2[66] = &hf_openhpsdr_e_ddcc_ddc_cic1_66;
       array3[66] = &hf_openhpsdr_e_ddcc_ddc_cic2_66;
       array4[66] = &hf_openhpsdr_e_ddcc_ddc_size66;
       array0[67] = &hf_openhpsdr_e_ddcc_ddc_asign67;
       array1[67] = &hf_openhpsdr_e_ddcc_ddc_rate67;
       array2[67] = &hf_openhpsdr_e_ddcc_ddc_cic1_67;
       array3[67] = &hf_openhpsdr_e_ddcc_ddc_cic2_67;
       array4[67] = &hf_openhpsdr_e_ddcc_ddc_size67;
       array0[68] = &hf_openhpsdr_e_ddcc_ddc_asign68;
       array1[68] = &hf_openhpsdr_e_ddcc_ddc_rate68;
       array2[68] = &hf_openhpsdr_e_ddcc_ddc_cic1_68;
       array3[68] = &hf_openhpsdr_e_ddcc_ddc_cic2_68;
       array4[68] = &hf_openhpsdr_e_ddcc_ddc_size68;
       array0[69] = &hf_openhpsdr_e_ddcc_ddc_asign69;
       array1[69] = &hf_openhpsdr_e_ddcc_ddc_rate69;
       array2[69] = &hf_openhpsdr_e_ddcc_ddc_cic1_69;
       array3[69] = &hf_openhpsdr_e_ddcc_ddc_cic2_69;
       array4[69] = &hf_openhpsdr_e_ddcc_ddc_size69;
       array0[70] = &hf_openhpsdr_e_ddcc_ddc_asign70;
       array1[70] = &hf_openhpsdr_e_ddcc_ddc_rate70;
       array2[70] = &hf_openhpsdr_e_ddcc_ddc_cic1_70;
       array3[70] = &hf_openhpsdr_e_ddcc_ddc_cic2_70;
       array4[70] = &hf_openhpsdr_e_ddcc_ddc_size70;
       array0[71] = &hf_openhpsdr_e_ddcc_ddc_asign71;
       array1[71] = &hf_openhpsdr_e_ddcc_ddc_rate71;
       array2[71] = &hf_openhpsdr_e_ddcc_ddc_cic1_71;
       array3[71] = &hf_openhpsdr_e_ddcc_ddc_cic2_71;
       array4[71] = &hf_openhpsdr_e_ddcc_ddc_size71;
       array0[72] = &hf_openhpsdr_e_ddcc_ddc_asign72;
       array1[72] = &hf_openhpsdr_e_ddcc_ddc_rate72;
       array2[72] = &hf_openhpsdr_e_ddcc_ddc_cic1_72;
       array3[72] = &hf_openhpsdr_e_ddcc_ddc_cic2_72;
       array4[72] = &hf_openhpsdr_e_ddcc_ddc_size72;
       array0[73] = &hf_openhpsdr_e_ddcc_ddc_asign73;
       array1[73] = &hf_openhpsdr_e_ddcc_ddc_rate73;
       array2[73] = &hf_openhpsdr_e_ddcc_ddc_cic1_73;
       array3[73] = &hf_openhpsdr_e_ddcc_ddc_cic2_73;
       array4[73] = &hf_openhpsdr_e_ddcc_ddc_size73;
       array0[74] = &hf_openhpsdr_e_ddcc_ddc_asign74;
       array1[74] = &hf_openhpsdr_e_ddcc_ddc_rate74;
       array2[74] = &hf_openhpsdr_e_ddcc_ddc_cic1_74;
       array3[74] = &hf_openhpsdr_e_ddcc_ddc_cic2_74;
       array4[74] = &hf_openhpsdr_e_ddcc_ddc_size74;
       array0[75] = &hf_openhpsdr_e_ddcc_ddc_asign75;
       array1[75] = &hf_openhpsdr_e_ddcc_ddc_rate75;
       array2[75] = &hf_openhpsdr_e_ddcc_ddc_cic1_75;
       array3[75] = &hf_openhpsdr_e_ddcc_ddc_cic2_75;
       array4[75] = &hf_openhpsdr_e_ddcc_ddc_size75;
       array0[76] = &hf_openhpsdr_e_ddcc_ddc_asign76;
       array1[76] = &hf_openhpsdr_e_ddcc_ddc_rate76;
       array2[76] = &hf_openhpsdr_e_ddcc_ddc_cic1_76;
       array3[76] = &hf_openhpsdr_e_ddcc_ddc_cic2_76;
       array4[76] = &hf_openhpsdr_e_ddcc_ddc_size76;
       array0[77] = &hf_openhpsdr_e_ddcc_ddc_asign77;
       array1[77] = &hf_openhpsdr_e_ddcc_ddc_rate77;
       array2[77] = &hf_openhpsdr_e_ddcc_ddc_cic1_77;
       array3[77] = &hf_openhpsdr_e_ddcc_ddc_cic2_77;
       array4[77] = &hf_openhpsdr_e_ddcc_ddc_size77;
       array0[78] = &hf_openhpsdr_e_ddcc_ddc_asign78;
       array1[78] = &hf_openhpsdr_e_ddcc_ddc_rate78;
       array2[78] = &hf_openhpsdr_e_ddcc_ddc_cic1_78;
       array3[78] = &hf_openhpsdr_e_ddcc_ddc_cic2_78;
       array4[78] = &hf_openhpsdr_e_ddcc_ddc_size78;
       array0[79] = &hf_openhpsdr_e_ddcc_ddc_asign79;
       array1[79] = &hf_openhpsdr_e_ddcc_ddc_rate79;
       array2[79] = &hf_openhpsdr_e_ddcc_ddc_cic1_79;
       array3[79] = &hf_openhpsdr_e_ddcc_ddc_cic2_79;
       array4[79] = &hf_openhpsdr_e_ddcc_ddc_size79;

       config_tree_ddcc_item = proto_tree_add_uint_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_config_sub, 
           tvb, offset,480, value,"DDC Configuration"); 
       openhpsdr_e_ddcc_config_tree = proto_item_add_subtree(config_tree_ddcc_item,ett_openhpsdr_e_ddcc_config);

       for (i=0;i<=79;i++) {

          proto_tree_add_item(openhpsdr_e_ddcc_config_tree, *array0[i], tvb,offset, 1, ENC_BIG_ENDIAN);           
          offset += 1;

          proto_tree_add_item(openhpsdr_e_ddcc_config_tree, *array1[i], tvb,offset, 2, ENC_BIG_ENDIAN);           
          offset += 2;
          
          append_text_item = proto_tree_add_item(openhpsdr_e_ddcc_config_tree, *array2[i], tvb,offset, 1, ENC_BIG_ENDIAN);
          proto_item_append_text(append_text_item,"  :Future Use");           
          offset += 1;

          append_text_item = proto_tree_add_item(openhpsdr_e_ddcc_config_tree, *array3[i], tvb,offset, 1, ENC_BIG_ENDIAN); 
          proto_item_append_text(append_text_item,"  :Future Use");           
          offset += 1;

          proto_tree_add_item(openhpsdr_e_ddcc_config_tree, *array4[i], tvb,offset, 1, ENC_BIG_ENDIAN);           
          offset += 1;
       }

       proto_tree_add_string_format(openhpsdr_e_ddcc_tree,hf_openhpsdr_e_reserved ,tvb,offset,866,placehold,
           "Reserved for Future Use: 866 Bytes");
       offset += 866;

       array0[0] = &hf_openhpsdr_e_ddcc_ddc_sync0_0;
       array1[0] = &hf_openhpsdr_e_ddcc_ddc_sync1_0;
       array2[0] = &hf_openhpsdr_e_ddcc_ddc_sync2_0;
       array3[0] = &hf_openhpsdr_e_ddcc_ddc_sync3_0;
       array4[0] = &hf_openhpsdr_e_ddcc_ddc_sync4_0;
       array5[0] = &hf_openhpsdr_e_ddcc_ddc_sync5_0;
       array6[0] = &hf_openhpsdr_e_ddcc_ddc_sync6_0;
       array7[0] = &hf_openhpsdr_e_ddcc_ddc_sync7_0;
       array0[1] = &hf_openhpsdr_e_ddcc_ddc_sync0_1;
       array1[1] = &hf_openhpsdr_e_ddcc_ddc_sync1_1;
       array2[1] = &hf_openhpsdr_e_ddcc_ddc_sync2_1;
       array3[1] = &hf_openhpsdr_e_ddcc_ddc_sync3_1;
       array4[1] = &hf_openhpsdr_e_ddcc_ddc_sync4_1;
       array5[1] = &hf_openhpsdr_e_ddcc_ddc_sync5_1;
       array6[1] = &hf_openhpsdr_e_ddcc_ddc_sync6_1;
       array7[1] = &hf_openhpsdr_e_ddcc_ddc_sync7_1;
       array0[2] = &hf_openhpsdr_e_ddcc_ddc_sync0_2;
       array1[2] = &hf_openhpsdr_e_ddcc_ddc_sync1_2;
       array2[2] = &hf_openhpsdr_e_ddcc_ddc_sync2_2;
       array3[2] = &hf_openhpsdr_e_ddcc_ddc_sync3_2;
       array4[2] = &hf_openhpsdr_e_ddcc_ddc_sync4_2;
       array5[2] = &hf_openhpsdr_e_ddcc_ddc_sync5_2;
       array6[2] = &hf_openhpsdr_e_ddcc_ddc_sync6_2;
       array7[2] = &hf_openhpsdr_e_ddcc_ddc_sync7_2;
       array0[3] = &hf_openhpsdr_e_ddcc_ddc_sync0_3;
       array1[3] = &hf_openhpsdr_e_ddcc_ddc_sync1_3;
       array2[3] = &hf_openhpsdr_e_ddcc_ddc_sync2_3;
       array3[3] = &hf_openhpsdr_e_ddcc_ddc_sync3_3;
       array4[3] = &hf_openhpsdr_e_ddcc_ddc_sync4_3;
       array5[3] = &hf_openhpsdr_e_ddcc_ddc_sync5_3;
       array6[3] = &hf_openhpsdr_e_ddcc_ddc_sync6_3;
       array7[3] = &hf_openhpsdr_e_ddcc_ddc_sync7_3;
       array0[4] = &hf_openhpsdr_e_ddcc_ddc_sync0_4;
       array1[4] = &hf_openhpsdr_e_ddcc_ddc_sync1_4;
       array2[4] = &hf_openhpsdr_e_ddcc_ddc_sync2_4;
       array3[4] = &hf_openhpsdr_e_ddcc_ddc_sync3_4;
       array4[4] = &hf_openhpsdr_e_ddcc_ddc_sync4_4;
       array5[4] = &hf_openhpsdr_e_ddcc_ddc_sync5_4;
       array6[4] = &hf_openhpsdr_e_ddcc_ddc_sync6_4;
       array7[4] = &hf_openhpsdr_e_ddcc_ddc_sync7_4;
       array0[5] = &hf_openhpsdr_e_ddcc_ddc_sync0_5;
       array1[5] = &hf_openhpsdr_e_ddcc_ddc_sync1_5;
       array2[5] = &hf_openhpsdr_e_ddcc_ddc_sync2_5;
       array3[5] = &hf_openhpsdr_e_ddcc_ddc_sync3_5;
       array4[5] = &hf_openhpsdr_e_ddcc_ddc_sync4_5;
       array5[5] = &hf_openhpsdr_e_ddcc_ddc_sync5_5;
       array6[5] = &hf_openhpsdr_e_ddcc_ddc_sync6_5;
       array7[5] = &hf_openhpsdr_e_ddcc_ddc_sync7_5;
       array0[6] = &hf_openhpsdr_e_ddcc_ddc_sync0_6;
       array1[6] = &hf_openhpsdr_e_ddcc_ddc_sync1_6;
       array2[6] = &hf_openhpsdr_e_ddcc_ddc_sync2_6;
       array3[6] = &hf_openhpsdr_e_ddcc_ddc_sync3_6;
       array4[6] = &hf_openhpsdr_e_ddcc_ddc_sync4_6;
       array5[6] = &hf_openhpsdr_e_ddcc_ddc_sync5_6;
       array6[6] = &hf_openhpsdr_e_ddcc_ddc_sync6_6;
       array7[6] = &hf_openhpsdr_e_ddcc_ddc_sync7_6;
       array0[7] = &hf_openhpsdr_e_ddcc_ddc_sync0_7;
       array1[7] = &hf_openhpsdr_e_ddcc_ddc_sync1_7;
       array2[7] = &hf_openhpsdr_e_ddcc_ddc_sync2_7;
       array3[7] = &hf_openhpsdr_e_ddcc_ddc_sync3_7;
       array4[7] = &hf_openhpsdr_e_ddcc_ddc_sync4_7;
       array5[7] = &hf_openhpsdr_e_ddcc_ddc_sync5_7;
       array6[7] = &hf_openhpsdr_e_ddcc_ddc_sync6_7;
       array7[7] = &hf_openhpsdr_e_ddcc_ddc_sync7_7;
       array0[8] = &hf_openhpsdr_e_ddcc_ddc_sync0_8;
       array1[8] = &hf_openhpsdr_e_ddcc_ddc_sync1_8;
       array2[8] = &hf_openhpsdr_e_ddcc_ddc_sync2_8;
       array3[8] = &hf_openhpsdr_e_ddcc_ddc_sync3_8;
       array4[8] = &hf_openhpsdr_e_ddcc_ddc_sync4_8;
       array5[8] = &hf_openhpsdr_e_ddcc_ddc_sync5_8;
       array6[8] = &hf_openhpsdr_e_ddcc_ddc_sync6_8;
       array7[8] = &hf_openhpsdr_e_ddcc_ddc_sync7_8;
       array0[9] = &hf_openhpsdr_e_ddcc_ddc_sync0_9;
       array1[9] = &hf_openhpsdr_e_ddcc_ddc_sync1_9;
       array2[9] = &hf_openhpsdr_e_ddcc_ddc_sync2_9;
       array3[9] = &hf_openhpsdr_e_ddcc_ddc_sync3_9;
       array4[9] = &hf_openhpsdr_e_ddcc_ddc_sync4_9;
       array5[9] = &hf_openhpsdr_e_ddcc_ddc_sync5_9;
       array6[9] = &hf_openhpsdr_e_ddcc_ddc_sync6_9;
       array7[9] = &hf_openhpsdr_e_ddcc_ddc_sync7_9;
       array0[10] = &hf_openhpsdr_e_ddcc_ddc_sync0_10;
       array1[10] = &hf_openhpsdr_e_ddcc_ddc_sync1_10;
       array2[10] = &hf_openhpsdr_e_ddcc_ddc_sync2_10;
       array3[10] = &hf_openhpsdr_e_ddcc_ddc_sync3_10;
       array4[10] = &hf_openhpsdr_e_ddcc_ddc_sync4_10;
       array5[10] = &hf_openhpsdr_e_ddcc_ddc_sync5_10;
       array6[10] = &hf_openhpsdr_e_ddcc_ddc_sync6_10;
       array7[10] = &hf_openhpsdr_e_ddcc_ddc_sync7_10;
       array0[11] = &hf_openhpsdr_e_ddcc_ddc_sync0_11;
       array1[11] = &hf_openhpsdr_e_ddcc_ddc_sync1_11;
       array2[11] = &hf_openhpsdr_e_ddcc_ddc_sync2_11;
       array3[11] = &hf_openhpsdr_e_ddcc_ddc_sync3_11;
       array4[11] = &hf_openhpsdr_e_ddcc_ddc_sync4_11;
       array5[11] = &hf_openhpsdr_e_ddcc_ddc_sync5_11;
       array6[11] = &hf_openhpsdr_e_ddcc_ddc_sync6_11;
       array7[11] = &hf_openhpsdr_e_ddcc_ddc_sync7_11;
       array0[12] = &hf_openhpsdr_e_ddcc_ddc_sync0_12;
       array1[12] = &hf_openhpsdr_e_ddcc_ddc_sync1_12;
       array2[12] = &hf_openhpsdr_e_ddcc_ddc_sync2_12;
       array3[12] = &hf_openhpsdr_e_ddcc_ddc_sync3_12;
       array4[12] = &hf_openhpsdr_e_ddcc_ddc_sync4_12;
       array5[12] = &hf_openhpsdr_e_ddcc_ddc_sync5_12;
       array6[12] = &hf_openhpsdr_e_ddcc_ddc_sync6_12;
       array7[12] = &hf_openhpsdr_e_ddcc_ddc_sync7_12;
       array0[13] = &hf_openhpsdr_e_ddcc_ddc_sync0_13;
       array1[13] = &hf_openhpsdr_e_ddcc_ddc_sync1_13;
       array2[13] = &hf_openhpsdr_e_ddcc_ddc_sync2_13;
       array3[13] = &hf_openhpsdr_e_ddcc_ddc_sync3_13;
       array4[13] = &hf_openhpsdr_e_ddcc_ddc_sync4_13;
       array5[13] = &hf_openhpsdr_e_ddcc_ddc_sync5_13;
       array6[13] = &hf_openhpsdr_e_ddcc_ddc_sync6_13;
       array7[13] = &hf_openhpsdr_e_ddcc_ddc_sync7_13;
       array0[14] = &hf_openhpsdr_e_ddcc_ddc_sync0_14;
       array1[14] = &hf_openhpsdr_e_ddcc_ddc_sync1_14;
       array2[14] = &hf_openhpsdr_e_ddcc_ddc_sync2_14;
       array3[14] = &hf_openhpsdr_e_ddcc_ddc_sync3_14;
       array4[14] = &hf_openhpsdr_e_ddcc_ddc_sync4_14;
       array5[14] = &hf_openhpsdr_e_ddcc_ddc_sync5_14;
       array6[14] = &hf_openhpsdr_e_ddcc_ddc_sync6_14;
       array7[14] = &hf_openhpsdr_e_ddcc_ddc_sync7_14;
       array0[15] = &hf_openhpsdr_e_ddcc_ddc_sync0_15;
       array1[15] = &hf_openhpsdr_e_ddcc_ddc_sync1_15;
       array2[15] = &hf_openhpsdr_e_ddcc_ddc_sync2_15;
       array3[15] = &hf_openhpsdr_e_ddcc_ddc_sync3_15;
       array4[15] = &hf_openhpsdr_e_ddcc_ddc_sync4_15;
       array5[15] = &hf_openhpsdr_e_ddcc_ddc_sync5_15;
       array6[15] = &hf_openhpsdr_e_ddcc_ddc_sync6_15;
       array7[15] = &hf_openhpsdr_e_ddcc_ddc_sync7_15;
       array0[16] = &hf_openhpsdr_e_ddcc_ddc_sync0_16;
       array1[16] = &hf_openhpsdr_e_ddcc_ddc_sync1_16;
       array2[16] = &hf_openhpsdr_e_ddcc_ddc_sync2_16;
       array3[16] = &hf_openhpsdr_e_ddcc_ddc_sync3_16;
       array4[16] = &hf_openhpsdr_e_ddcc_ddc_sync4_16;
       array5[16] = &hf_openhpsdr_e_ddcc_ddc_sync5_16;
       array6[16] = &hf_openhpsdr_e_ddcc_ddc_sync6_16;
       array7[16] = &hf_openhpsdr_e_ddcc_ddc_sync7_16;
       array0[17] = &hf_openhpsdr_e_ddcc_ddc_sync0_17;
       array1[17] = &hf_openhpsdr_e_ddcc_ddc_sync1_17;
       array2[17] = &hf_openhpsdr_e_ddcc_ddc_sync2_17;
       array3[17] = &hf_openhpsdr_e_ddcc_ddc_sync3_17;
       array4[17] = &hf_openhpsdr_e_ddcc_ddc_sync4_17;
       array5[17] = &hf_openhpsdr_e_ddcc_ddc_sync5_17;
       array6[17] = &hf_openhpsdr_e_ddcc_ddc_sync6_17;
       array7[17] = &hf_openhpsdr_e_ddcc_ddc_sync7_17;
       array0[18] = &hf_openhpsdr_e_ddcc_ddc_sync0_18;
       array1[18] = &hf_openhpsdr_e_ddcc_ddc_sync1_18;
       array2[18] = &hf_openhpsdr_e_ddcc_ddc_sync2_18;
       array3[18] = &hf_openhpsdr_e_ddcc_ddc_sync3_18;
       array4[18] = &hf_openhpsdr_e_ddcc_ddc_sync4_18;
       array5[18] = &hf_openhpsdr_e_ddcc_ddc_sync5_18;
       array6[18] = &hf_openhpsdr_e_ddcc_ddc_sync6_18;
       array7[18] = &hf_openhpsdr_e_ddcc_ddc_sync7_18;
       array0[19] = &hf_openhpsdr_e_ddcc_ddc_sync0_19;
       array1[19] = &hf_openhpsdr_e_ddcc_ddc_sync1_19;
       array2[19] = &hf_openhpsdr_e_ddcc_ddc_sync2_19;
       array3[19] = &hf_openhpsdr_e_ddcc_ddc_sync3_19;
       array4[19] = &hf_openhpsdr_e_ddcc_ddc_sync4_19;
       array5[19] = &hf_openhpsdr_e_ddcc_ddc_sync5_19;
       array6[19] = &hf_openhpsdr_e_ddcc_ddc_sync6_19;
       array7[19] = &hf_openhpsdr_e_ddcc_ddc_sync7_19;
       array0[20] = &hf_openhpsdr_e_ddcc_ddc_sync0_20;
       array1[20] = &hf_openhpsdr_e_ddcc_ddc_sync1_20;
       array2[20] = &hf_openhpsdr_e_ddcc_ddc_sync2_20;
       array3[20] = &hf_openhpsdr_e_ddcc_ddc_sync3_20;
       array4[20] = &hf_openhpsdr_e_ddcc_ddc_sync4_20;
       array5[20] = &hf_openhpsdr_e_ddcc_ddc_sync5_20;
       array6[20] = &hf_openhpsdr_e_ddcc_ddc_sync6_20;
       array7[20] = &hf_openhpsdr_e_ddcc_ddc_sync7_20;
       array0[21] = &hf_openhpsdr_e_ddcc_ddc_sync0_21;
       array1[21] = &hf_openhpsdr_e_ddcc_ddc_sync1_21;
       array2[21] = &hf_openhpsdr_e_ddcc_ddc_sync2_21;
       array3[21] = &hf_openhpsdr_e_ddcc_ddc_sync3_21;
       array4[21] = &hf_openhpsdr_e_ddcc_ddc_sync4_21;
       array5[21] = &hf_openhpsdr_e_ddcc_ddc_sync5_21;
       array6[21] = &hf_openhpsdr_e_ddcc_ddc_sync6_21;
       array7[21] = &hf_openhpsdr_e_ddcc_ddc_sync7_21;
       array0[22] = &hf_openhpsdr_e_ddcc_ddc_sync0_22;
       array1[22] = &hf_openhpsdr_e_ddcc_ddc_sync1_22;
       array2[22] = &hf_openhpsdr_e_ddcc_ddc_sync2_22;
       array3[22] = &hf_openhpsdr_e_ddcc_ddc_sync3_22;
       array4[22] = &hf_openhpsdr_e_ddcc_ddc_sync4_22;
       array5[22] = &hf_openhpsdr_e_ddcc_ddc_sync5_22;
       array6[22] = &hf_openhpsdr_e_ddcc_ddc_sync6_22;
       array7[22] = &hf_openhpsdr_e_ddcc_ddc_sync7_22;
       array0[23] = &hf_openhpsdr_e_ddcc_ddc_sync0_23;
       array1[23] = &hf_openhpsdr_e_ddcc_ddc_sync1_23;
       array2[23] = &hf_openhpsdr_e_ddcc_ddc_sync2_23;
       array3[23] = &hf_openhpsdr_e_ddcc_ddc_sync3_23;
       array4[23] = &hf_openhpsdr_e_ddcc_ddc_sync4_23;
       array5[23] = &hf_openhpsdr_e_ddcc_ddc_sync5_23;
       array6[23] = &hf_openhpsdr_e_ddcc_ddc_sync6_23;
       array7[23] = &hf_openhpsdr_e_ddcc_ddc_sync7_23;
       array0[24] = &hf_openhpsdr_e_ddcc_ddc_sync0_24;
       array1[24] = &hf_openhpsdr_e_ddcc_ddc_sync1_24;
       array2[24] = &hf_openhpsdr_e_ddcc_ddc_sync2_24;
       array3[24] = &hf_openhpsdr_e_ddcc_ddc_sync3_24;
       array4[24] = &hf_openhpsdr_e_ddcc_ddc_sync4_24;
       array5[24] = &hf_openhpsdr_e_ddcc_ddc_sync5_24;
       array6[24] = &hf_openhpsdr_e_ddcc_ddc_sync6_24;
       array7[24] = &hf_openhpsdr_e_ddcc_ddc_sync7_24;
       array0[25] = &hf_openhpsdr_e_ddcc_ddc_sync0_25;
       array1[25] = &hf_openhpsdr_e_ddcc_ddc_sync1_25;
       array2[25] = &hf_openhpsdr_e_ddcc_ddc_sync2_25;
       array3[25] = &hf_openhpsdr_e_ddcc_ddc_sync3_25;
       array4[25] = &hf_openhpsdr_e_ddcc_ddc_sync4_25;
       array5[25] = &hf_openhpsdr_e_ddcc_ddc_sync5_25;
       array6[25] = &hf_openhpsdr_e_ddcc_ddc_sync6_25;
       array7[25] = &hf_openhpsdr_e_ddcc_ddc_sync7_25;
       array0[26] = &hf_openhpsdr_e_ddcc_ddc_sync0_26;
       array1[26] = &hf_openhpsdr_e_ddcc_ddc_sync1_26;
       array2[26] = &hf_openhpsdr_e_ddcc_ddc_sync2_26;
       array3[26] = &hf_openhpsdr_e_ddcc_ddc_sync3_26;
       array4[26] = &hf_openhpsdr_e_ddcc_ddc_sync4_26;
       array5[26] = &hf_openhpsdr_e_ddcc_ddc_sync5_26;
       array6[26] = &hf_openhpsdr_e_ddcc_ddc_sync6_26;
       array7[26] = &hf_openhpsdr_e_ddcc_ddc_sync7_26;
       array0[27] = &hf_openhpsdr_e_ddcc_ddc_sync0_27;
       array1[27] = &hf_openhpsdr_e_ddcc_ddc_sync1_27;
       array2[27] = &hf_openhpsdr_e_ddcc_ddc_sync2_27;
       array3[27] = &hf_openhpsdr_e_ddcc_ddc_sync3_27;
       array4[27] = &hf_openhpsdr_e_ddcc_ddc_sync4_27;
       array5[27] = &hf_openhpsdr_e_ddcc_ddc_sync5_27;
       array6[27] = &hf_openhpsdr_e_ddcc_ddc_sync6_27;
       array7[27] = &hf_openhpsdr_e_ddcc_ddc_sync7_27;
       array0[28] = &hf_openhpsdr_e_ddcc_ddc_sync0_28;
       array1[28] = &hf_openhpsdr_e_ddcc_ddc_sync1_28;
       array2[28] = &hf_openhpsdr_e_ddcc_ddc_sync2_28;
       array3[28] = &hf_openhpsdr_e_ddcc_ddc_sync3_28;
       array4[28] = &hf_openhpsdr_e_ddcc_ddc_sync4_28;
       array5[28] = &hf_openhpsdr_e_ddcc_ddc_sync5_28;
       array6[28] = &hf_openhpsdr_e_ddcc_ddc_sync6_28;
       array7[28] = &hf_openhpsdr_e_ddcc_ddc_sync7_28;
       array0[29] = &hf_openhpsdr_e_ddcc_ddc_sync0_29;
       array1[29] = &hf_openhpsdr_e_ddcc_ddc_sync1_29;
       array2[29] = &hf_openhpsdr_e_ddcc_ddc_sync2_29;
       array3[29] = &hf_openhpsdr_e_ddcc_ddc_sync3_29;
       array4[29] = &hf_openhpsdr_e_ddcc_ddc_sync4_29;
       array5[29] = &hf_openhpsdr_e_ddcc_ddc_sync5_29;
       array6[29] = &hf_openhpsdr_e_ddcc_ddc_sync6_29;
       array7[29] = &hf_openhpsdr_e_ddcc_ddc_sync7_29;
       array0[30] = &hf_openhpsdr_e_ddcc_ddc_sync0_30;
       array1[30] = &hf_openhpsdr_e_ddcc_ddc_sync1_30;
       array2[30] = &hf_openhpsdr_e_ddcc_ddc_sync2_30;
       array3[30] = &hf_openhpsdr_e_ddcc_ddc_sync3_30;
       array4[30] = &hf_openhpsdr_e_ddcc_ddc_sync4_30;
       array5[30] = &hf_openhpsdr_e_ddcc_ddc_sync5_30;
       array6[30] = &hf_openhpsdr_e_ddcc_ddc_sync6_30;
       array7[30] = &hf_openhpsdr_e_ddcc_ddc_sync7_30;
       array0[31] = &hf_openhpsdr_e_ddcc_ddc_sync0_31;
       array1[31] = &hf_openhpsdr_e_ddcc_ddc_sync1_31;
       array2[31] = &hf_openhpsdr_e_ddcc_ddc_sync2_31;
       array3[31] = &hf_openhpsdr_e_ddcc_ddc_sync3_31;
       array4[31] = &hf_openhpsdr_e_ddcc_ddc_sync4_31;
       array5[31] = &hf_openhpsdr_e_ddcc_ddc_sync5_31;
       array6[31] = &hf_openhpsdr_e_ddcc_ddc_sync6_31;
       array7[31] = &hf_openhpsdr_e_ddcc_ddc_sync7_31;
       array0[32] = &hf_openhpsdr_e_ddcc_ddc_sync0_32;
       array1[32] = &hf_openhpsdr_e_ddcc_ddc_sync1_32;
       array2[32] = &hf_openhpsdr_e_ddcc_ddc_sync2_32;
       array3[32] = &hf_openhpsdr_e_ddcc_ddc_sync3_32;
       array4[32] = &hf_openhpsdr_e_ddcc_ddc_sync4_32;
       array5[32] = &hf_openhpsdr_e_ddcc_ddc_sync5_32;
       array6[32] = &hf_openhpsdr_e_ddcc_ddc_sync6_32;
       array7[32] = &hf_openhpsdr_e_ddcc_ddc_sync7_32;
       array0[33] = &hf_openhpsdr_e_ddcc_ddc_sync0_33;
       array1[33] = &hf_openhpsdr_e_ddcc_ddc_sync1_33;
       array2[33] = &hf_openhpsdr_e_ddcc_ddc_sync2_33;
       array3[33] = &hf_openhpsdr_e_ddcc_ddc_sync3_33;
       array4[33] = &hf_openhpsdr_e_ddcc_ddc_sync4_33;
       array5[33] = &hf_openhpsdr_e_ddcc_ddc_sync5_33;
       array6[33] = &hf_openhpsdr_e_ddcc_ddc_sync6_33;
       array7[33] = &hf_openhpsdr_e_ddcc_ddc_sync7_33;
       array0[34] = &hf_openhpsdr_e_ddcc_ddc_sync0_34;
       array1[34] = &hf_openhpsdr_e_ddcc_ddc_sync1_34;
       array2[34] = &hf_openhpsdr_e_ddcc_ddc_sync2_34;
       array3[34] = &hf_openhpsdr_e_ddcc_ddc_sync3_34;
       array4[34] = &hf_openhpsdr_e_ddcc_ddc_sync4_34;
       array5[34] = &hf_openhpsdr_e_ddcc_ddc_sync5_34;
       array6[34] = &hf_openhpsdr_e_ddcc_ddc_sync6_34;
       array7[34] = &hf_openhpsdr_e_ddcc_ddc_sync7_34;
       array0[35] = &hf_openhpsdr_e_ddcc_ddc_sync0_35;
       array1[35] = &hf_openhpsdr_e_ddcc_ddc_sync1_35;
       array2[35] = &hf_openhpsdr_e_ddcc_ddc_sync2_35;
       array3[35] = &hf_openhpsdr_e_ddcc_ddc_sync3_35;
       array4[35] = &hf_openhpsdr_e_ddcc_ddc_sync4_35;
       array5[35] = &hf_openhpsdr_e_ddcc_ddc_sync5_35;
       array6[35] = &hf_openhpsdr_e_ddcc_ddc_sync6_35;
       array7[35] = &hf_openhpsdr_e_ddcc_ddc_sync7_35;
       array0[36] = &hf_openhpsdr_e_ddcc_ddc_sync0_36;
       array1[36] = &hf_openhpsdr_e_ddcc_ddc_sync1_36;
       array2[36] = &hf_openhpsdr_e_ddcc_ddc_sync2_36;
       array3[36] = &hf_openhpsdr_e_ddcc_ddc_sync3_36;
       array4[36] = &hf_openhpsdr_e_ddcc_ddc_sync4_36;
       array5[36] = &hf_openhpsdr_e_ddcc_ddc_sync5_36;
       array6[36] = &hf_openhpsdr_e_ddcc_ddc_sync6_36;
       array7[36] = &hf_openhpsdr_e_ddcc_ddc_sync7_36;
       array0[37] = &hf_openhpsdr_e_ddcc_ddc_sync0_37;
       array1[37] = &hf_openhpsdr_e_ddcc_ddc_sync1_37;
       array2[37] = &hf_openhpsdr_e_ddcc_ddc_sync2_37;
       array3[37] = &hf_openhpsdr_e_ddcc_ddc_sync3_37;
       array4[37] = &hf_openhpsdr_e_ddcc_ddc_sync4_37;
       array5[37] = &hf_openhpsdr_e_ddcc_ddc_sync5_37;
       array6[37] = &hf_openhpsdr_e_ddcc_ddc_sync6_37;
       array7[37] = &hf_openhpsdr_e_ddcc_ddc_sync7_37;
       array0[38] = &hf_openhpsdr_e_ddcc_ddc_sync0_38;
       array1[38] = &hf_openhpsdr_e_ddcc_ddc_sync1_38;
       array2[38] = &hf_openhpsdr_e_ddcc_ddc_sync2_38;
       array3[38] = &hf_openhpsdr_e_ddcc_ddc_sync3_38;
       array4[38] = &hf_openhpsdr_e_ddcc_ddc_sync4_38;
       array5[38] = &hf_openhpsdr_e_ddcc_ddc_sync5_38;
       array6[38] = &hf_openhpsdr_e_ddcc_ddc_sync6_38;
       array7[38] = &hf_openhpsdr_e_ddcc_ddc_sync7_38;
       array0[39] = &hf_openhpsdr_e_ddcc_ddc_sync0_39;
       array1[39] = &hf_openhpsdr_e_ddcc_ddc_sync1_39;
       array2[39] = &hf_openhpsdr_e_ddcc_ddc_sync2_39;
       array3[39] = &hf_openhpsdr_e_ddcc_ddc_sync3_39;
       array4[39] = &hf_openhpsdr_e_ddcc_ddc_sync4_39;
       array5[39] = &hf_openhpsdr_e_ddcc_ddc_sync5_39;
       array6[39] = &hf_openhpsdr_e_ddcc_ddc_sync6_39;
       array7[39] = &hf_openhpsdr_e_ddcc_ddc_sync7_39;
       array0[40] = &hf_openhpsdr_e_ddcc_ddc_sync0_40;
       array1[40] = &hf_openhpsdr_e_ddcc_ddc_sync1_40;
       array2[40] = &hf_openhpsdr_e_ddcc_ddc_sync2_40;
       array3[40] = &hf_openhpsdr_e_ddcc_ddc_sync3_40;
       array4[40] = &hf_openhpsdr_e_ddcc_ddc_sync4_40;
       array5[40] = &hf_openhpsdr_e_ddcc_ddc_sync5_40;
       array6[40] = &hf_openhpsdr_e_ddcc_ddc_sync6_40;
       array7[40] = &hf_openhpsdr_e_ddcc_ddc_sync7_40;
       array0[41] = &hf_openhpsdr_e_ddcc_ddc_sync0_41;
       array1[41] = &hf_openhpsdr_e_ddcc_ddc_sync1_41;
       array2[41] = &hf_openhpsdr_e_ddcc_ddc_sync2_41;
       array3[41] = &hf_openhpsdr_e_ddcc_ddc_sync3_41;
       array4[41] = &hf_openhpsdr_e_ddcc_ddc_sync4_41;
       array5[41] = &hf_openhpsdr_e_ddcc_ddc_sync5_41;
       array6[41] = &hf_openhpsdr_e_ddcc_ddc_sync6_41;
       array7[41] = &hf_openhpsdr_e_ddcc_ddc_sync7_41;
       array0[42] = &hf_openhpsdr_e_ddcc_ddc_sync0_42;
       array1[42] = &hf_openhpsdr_e_ddcc_ddc_sync1_42;
       array2[42] = &hf_openhpsdr_e_ddcc_ddc_sync2_42;
       array3[42] = &hf_openhpsdr_e_ddcc_ddc_sync3_42;
       array4[42] = &hf_openhpsdr_e_ddcc_ddc_sync4_42;
       array5[42] = &hf_openhpsdr_e_ddcc_ddc_sync5_42;
       array6[42] = &hf_openhpsdr_e_ddcc_ddc_sync6_42;
       array7[42] = &hf_openhpsdr_e_ddcc_ddc_sync7_42;
       array0[43] = &hf_openhpsdr_e_ddcc_ddc_sync0_43;
       array1[43] = &hf_openhpsdr_e_ddcc_ddc_sync1_43;
       array2[43] = &hf_openhpsdr_e_ddcc_ddc_sync2_43;
       array3[43] = &hf_openhpsdr_e_ddcc_ddc_sync3_43;
       array4[43] = &hf_openhpsdr_e_ddcc_ddc_sync4_43;
       array5[43] = &hf_openhpsdr_e_ddcc_ddc_sync5_43;
       array6[43] = &hf_openhpsdr_e_ddcc_ddc_sync6_43;
       array7[43] = &hf_openhpsdr_e_ddcc_ddc_sync7_43;
       array0[44] = &hf_openhpsdr_e_ddcc_ddc_sync0_44;
       array1[44] = &hf_openhpsdr_e_ddcc_ddc_sync1_44;
       array2[44] = &hf_openhpsdr_e_ddcc_ddc_sync2_44;
       array3[44] = &hf_openhpsdr_e_ddcc_ddc_sync3_44;
       array4[44] = &hf_openhpsdr_e_ddcc_ddc_sync4_44;
       array5[44] = &hf_openhpsdr_e_ddcc_ddc_sync5_44;
       array6[44] = &hf_openhpsdr_e_ddcc_ddc_sync6_44;
       array7[44] = &hf_openhpsdr_e_ddcc_ddc_sync7_44;
       array0[45] = &hf_openhpsdr_e_ddcc_ddc_sync0_45;
       array1[45] = &hf_openhpsdr_e_ddcc_ddc_sync1_45;
       array2[45] = &hf_openhpsdr_e_ddcc_ddc_sync2_45;
       array3[45] = &hf_openhpsdr_e_ddcc_ddc_sync3_45;
       array4[45] = &hf_openhpsdr_e_ddcc_ddc_sync4_45;
       array5[45] = &hf_openhpsdr_e_ddcc_ddc_sync5_45;
       array6[45] = &hf_openhpsdr_e_ddcc_ddc_sync6_45;
       array7[45] = &hf_openhpsdr_e_ddcc_ddc_sync7_45;
       array0[46] = &hf_openhpsdr_e_ddcc_ddc_sync0_46;
       array1[46] = &hf_openhpsdr_e_ddcc_ddc_sync1_46;
       array2[46] = &hf_openhpsdr_e_ddcc_ddc_sync2_46;
       array3[46] = &hf_openhpsdr_e_ddcc_ddc_sync3_46;
       array4[46] = &hf_openhpsdr_e_ddcc_ddc_sync4_46;
       array5[46] = &hf_openhpsdr_e_ddcc_ddc_sync5_46;
       array6[46] = &hf_openhpsdr_e_ddcc_ddc_sync6_46;
       array7[46] = &hf_openhpsdr_e_ddcc_ddc_sync7_46;
       array0[47] = &hf_openhpsdr_e_ddcc_ddc_sync0_47;
       array1[47] = &hf_openhpsdr_e_ddcc_ddc_sync1_47;
       array2[47] = &hf_openhpsdr_e_ddcc_ddc_sync2_47;
       array3[47] = &hf_openhpsdr_e_ddcc_ddc_sync3_47;
       array4[47] = &hf_openhpsdr_e_ddcc_ddc_sync4_47;
       array5[47] = &hf_openhpsdr_e_ddcc_ddc_sync5_47;
       array6[47] = &hf_openhpsdr_e_ddcc_ddc_sync6_47;
       array7[47] = &hf_openhpsdr_e_ddcc_ddc_sync7_47;
       array0[48] = &hf_openhpsdr_e_ddcc_ddc_sync0_48;
       array1[48] = &hf_openhpsdr_e_ddcc_ddc_sync1_48;
       array2[48] = &hf_openhpsdr_e_ddcc_ddc_sync2_48;
       array3[48] = &hf_openhpsdr_e_ddcc_ddc_sync3_48;
       array4[48] = &hf_openhpsdr_e_ddcc_ddc_sync4_48;
       array5[48] = &hf_openhpsdr_e_ddcc_ddc_sync5_48;
       array6[48] = &hf_openhpsdr_e_ddcc_ddc_sync6_48;
       array7[48] = &hf_openhpsdr_e_ddcc_ddc_sync7_48;
       array0[49] = &hf_openhpsdr_e_ddcc_ddc_sync0_49;
       array1[49] = &hf_openhpsdr_e_ddcc_ddc_sync1_49;
       array2[49] = &hf_openhpsdr_e_ddcc_ddc_sync2_49;
       array3[49] = &hf_openhpsdr_e_ddcc_ddc_sync3_49;
       array4[49] = &hf_openhpsdr_e_ddcc_ddc_sync4_49;
       array5[49] = &hf_openhpsdr_e_ddcc_ddc_sync5_49;
       array6[49] = &hf_openhpsdr_e_ddcc_ddc_sync6_49;
       array7[49] = &hf_openhpsdr_e_ddcc_ddc_sync7_49;
       array0[50] = &hf_openhpsdr_e_ddcc_ddc_sync0_50;
       array1[50] = &hf_openhpsdr_e_ddcc_ddc_sync1_50;
       array2[50] = &hf_openhpsdr_e_ddcc_ddc_sync2_50;
       array3[50] = &hf_openhpsdr_e_ddcc_ddc_sync3_50;
       array4[50] = &hf_openhpsdr_e_ddcc_ddc_sync4_50;
       array5[50] = &hf_openhpsdr_e_ddcc_ddc_sync5_50;
       array6[50] = &hf_openhpsdr_e_ddcc_ddc_sync6_50;
       array7[50] = &hf_openhpsdr_e_ddcc_ddc_sync7_50;
       array0[51] = &hf_openhpsdr_e_ddcc_ddc_sync0_51;
       array1[51] = &hf_openhpsdr_e_ddcc_ddc_sync1_51;
       array2[51] = &hf_openhpsdr_e_ddcc_ddc_sync2_51;
       array3[51] = &hf_openhpsdr_e_ddcc_ddc_sync3_51;
       array4[51] = &hf_openhpsdr_e_ddcc_ddc_sync4_51;
       array5[51] = &hf_openhpsdr_e_ddcc_ddc_sync5_51;
       array6[51] = &hf_openhpsdr_e_ddcc_ddc_sync6_51;
       array7[51] = &hf_openhpsdr_e_ddcc_ddc_sync7_51;
       array0[52] = &hf_openhpsdr_e_ddcc_ddc_sync0_52;
       array1[52] = &hf_openhpsdr_e_ddcc_ddc_sync1_52;
       array2[52] = &hf_openhpsdr_e_ddcc_ddc_sync2_52;
       array3[52] = &hf_openhpsdr_e_ddcc_ddc_sync3_52;
       array4[52] = &hf_openhpsdr_e_ddcc_ddc_sync4_52;
       array5[52] = &hf_openhpsdr_e_ddcc_ddc_sync5_52;
       array6[52] = &hf_openhpsdr_e_ddcc_ddc_sync6_52;
       array7[52] = &hf_openhpsdr_e_ddcc_ddc_sync7_52;
       array0[53] = &hf_openhpsdr_e_ddcc_ddc_sync0_53;
       array1[53] = &hf_openhpsdr_e_ddcc_ddc_sync1_53;
       array2[53] = &hf_openhpsdr_e_ddcc_ddc_sync2_53;
       array3[53] = &hf_openhpsdr_e_ddcc_ddc_sync3_53;
       array4[53] = &hf_openhpsdr_e_ddcc_ddc_sync4_53;
       array5[53] = &hf_openhpsdr_e_ddcc_ddc_sync5_53;
       array6[53] = &hf_openhpsdr_e_ddcc_ddc_sync6_53;
       array7[53] = &hf_openhpsdr_e_ddcc_ddc_sync7_53;
       array0[54] = &hf_openhpsdr_e_ddcc_ddc_sync0_54;
       array1[54] = &hf_openhpsdr_e_ddcc_ddc_sync1_54;
       array2[54] = &hf_openhpsdr_e_ddcc_ddc_sync2_54;
       array3[54] = &hf_openhpsdr_e_ddcc_ddc_sync3_54;
       array4[54] = &hf_openhpsdr_e_ddcc_ddc_sync4_54;
       array5[54] = &hf_openhpsdr_e_ddcc_ddc_sync5_54;
       array6[54] = &hf_openhpsdr_e_ddcc_ddc_sync6_54;
       array7[54] = &hf_openhpsdr_e_ddcc_ddc_sync7_54;
       array0[55] = &hf_openhpsdr_e_ddcc_ddc_sync0_55;
       array1[55] = &hf_openhpsdr_e_ddcc_ddc_sync1_55;
       array2[55] = &hf_openhpsdr_e_ddcc_ddc_sync2_55;
       array3[55] = &hf_openhpsdr_e_ddcc_ddc_sync3_55;
       array4[55] = &hf_openhpsdr_e_ddcc_ddc_sync4_55;
       array5[55] = &hf_openhpsdr_e_ddcc_ddc_sync5_55;
       array6[55] = &hf_openhpsdr_e_ddcc_ddc_sync6_55;
       array7[55] = &hf_openhpsdr_e_ddcc_ddc_sync7_55;
       array0[56] = &hf_openhpsdr_e_ddcc_ddc_sync0_56;
       array1[56] = &hf_openhpsdr_e_ddcc_ddc_sync1_56;
       array2[56] = &hf_openhpsdr_e_ddcc_ddc_sync2_56;
       array3[56] = &hf_openhpsdr_e_ddcc_ddc_sync3_56;
       array4[56] = &hf_openhpsdr_e_ddcc_ddc_sync4_56;
       array5[56] = &hf_openhpsdr_e_ddcc_ddc_sync5_56;
       array6[56] = &hf_openhpsdr_e_ddcc_ddc_sync6_56;
       array7[56] = &hf_openhpsdr_e_ddcc_ddc_sync7_56;
       array0[57] = &hf_openhpsdr_e_ddcc_ddc_sync0_57;
       array1[57] = &hf_openhpsdr_e_ddcc_ddc_sync1_57;
       array2[57] = &hf_openhpsdr_e_ddcc_ddc_sync2_57;
       array3[57] = &hf_openhpsdr_e_ddcc_ddc_sync3_57;
       array4[57] = &hf_openhpsdr_e_ddcc_ddc_sync4_57;
       array5[57] = &hf_openhpsdr_e_ddcc_ddc_sync5_57;
       array6[57] = &hf_openhpsdr_e_ddcc_ddc_sync6_57;
       array7[57] = &hf_openhpsdr_e_ddcc_ddc_sync7_57;
       array0[58] = &hf_openhpsdr_e_ddcc_ddc_sync0_58;
       array1[58] = &hf_openhpsdr_e_ddcc_ddc_sync1_58;
       array2[58] = &hf_openhpsdr_e_ddcc_ddc_sync2_58;
       array3[58] = &hf_openhpsdr_e_ddcc_ddc_sync3_58;
       array4[58] = &hf_openhpsdr_e_ddcc_ddc_sync4_58;
       array5[58] = &hf_openhpsdr_e_ddcc_ddc_sync5_58;
       array6[58] = &hf_openhpsdr_e_ddcc_ddc_sync6_58;
       array7[58] = &hf_openhpsdr_e_ddcc_ddc_sync7_58;
       array0[59] = &hf_openhpsdr_e_ddcc_ddc_sync0_59;
       array1[59] = &hf_openhpsdr_e_ddcc_ddc_sync1_59;
       array2[59] = &hf_openhpsdr_e_ddcc_ddc_sync2_59;
       array3[59] = &hf_openhpsdr_e_ddcc_ddc_sync3_59;
       array4[59] = &hf_openhpsdr_e_ddcc_ddc_sync4_59;
       array5[59] = &hf_openhpsdr_e_ddcc_ddc_sync5_59;
       array6[59] = &hf_openhpsdr_e_ddcc_ddc_sync6_59;
       array7[59] = &hf_openhpsdr_e_ddcc_ddc_sync7_59;
       array0[60] = &hf_openhpsdr_e_ddcc_ddc_sync0_60;
       array1[60] = &hf_openhpsdr_e_ddcc_ddc_sync1_60;
       array2[60] = &hf_openhpsdr_e_ddcc_ddc_sync2_60;
       array3[60] = &hf_openhpsdr_e_ddcc_ddc_sync3_60;
       array4[60] = &hf_openhpsdr_e_ddcc_ddc_sync4_60;
       array5[60] = &hf_openhpsdr_e_ddcc_ddc_sync5_60;
       array6[60] = &hf_openhpsdr_e_ddcc_ddc_sync6_60;
       array7[60] = &hf_openhpsdr_e_ddcc_ddc_sync7_60;
       array0[61] = &hf_openhpsdr_e_ddcc_ddc_sync0_61;
       array1[61] = &hf_openhpsdr_e_ddcc_ddc_sync1_61;
       array2[61] = &hf_openhpsdr_e_ddcc_ddc_sync2_61;
       array3[61] = &hf_openhpsdr_e_ddcc_ddc_sync3_61;
       array4[61] = &hf_openhpsdr_e_ddcc_ddc_sync4_61;
       array5[61] = &hf_openhpsdr_e_ddcc_ddc_sync5_61;
       array6[61] = &hf_openhpsdr_e_ddcc_ddc_sync6_61;
       array7[61] = &hf_openhpsdr_e_ddcc_ddc_sync7_61;
       array0[62] = &hf_openhpsdr_e_ddcc_ddc_sync0_62;
       array1[62] = &hf_openhpsdr_e_ddcc_ddc_sync1_62;
       array2[62] = &hf_openhpsdr_e_ddcc_ddc_sync2_62;
       array3[62] = &hf_openhpsdr_e_ddcc_ddc_sync3_62;
       array4[62] = &hf_openhpsdr_e_ddcc_ddc_sync4_62;
       array5[62] = &hf_openhpsdr_e_ddcc_ddc_sync5_62;
       array6[62] = &hf_openhpsdr_e_ddcc_ddc_sync6_62;
       array7[62] = &hf_openhpsdr_e_ddcc_ddc_sync7_62;
       array0[63] = &hf_openhpsdr_e_ddcc_ddc_sync0_63;
       array1[63] = &hf_openhpsdr_e_ddcc_ddc_sync1_63;
       array2[63] = &hf_openhpsdr_e_ddcc_ddc_sync2_63;
       array3[63] = &hf_openhpsdr_e_ddcc_ddc_sync3_63;
       array4[63] = &hf_openhpsdr_e_ddcc_ddc_sync4_63;
       array5[63] = &hf_openhpsdr_e_ddcc_ddc_sync5_63;
       array6[63] = &hf_openhpsdr_e_ddcc_ddc_sync6_63;
       array7[63] = &hf_openhpsdr_e_ddcc_ddc_sync7_63;
       array0[64] = &hf_openhpsdr_e_ddcc_ddc_sync0_64;
       array1[64] = &hf_openhpsdr_e_ddcc_ddc_sync1_64;
       array2[64] = &hf_openhpsdr_e_ddcc_ddc_sync2_64;
       array3[64] = &hf_openhpsdr_e_ddcc_ddc_sync3_64;
       array4[64] = &hf_openhpsdr_e_ddcc_ddc_sync4_64;
       array5[64] = &hf_openhpsdr_e_ddcc_ddc_sync5_64;
       array6[64] = &hf_openhpsdr_e_ddcc_ddc_sync6_64;
       array7[64] = &hf_openhpsdr_e_ddcc_ddc_sync7_64;
       array0[65] = &hf_openhpsdr_e_ddcc_ddc_sync0_65;
       array1[65] = &hf_openhpsdr_e_ddcc_ddc_sync1_65;
       array2[65] = &hf_openhpsdr_e_ddcc_ddc_sync2_65;
       array3[65] = &hf_openhpsdr_e_ddcc_ddc_sync3_65;
       array4[65] = &hf_openhpsdr_e_ddcc_ddc_sync4_65;
       array5[65] = &hf_openhpsdr_e_ddcc_ddc_sync5_65;
       array6[65] = &hf_openhpsdr_e_ddcc_ddc_sync6_65;
       array7[65] = &hf_openhpsdr_e_ddcc_ddc_sync7_65;
       array0[66] = &hf_openhpsdr_e_ddcc_ddc_sync0_66;
       array1[66] = &hf_openhpsdr_e_ddcc_ddc_sync1_66;
       array2[66] = &hf_openhpsdr_e_ddcc_ddc_sync2_66;
       array3[66] = &hf_openhpsdr_e_ddcc_ddc_sync3_66;
       array4[66] = &hf_openhpsdr_e_ddcc_ddc_sync4_66;
       array5[66] = &hf_openhpsdr_e_ddcc_ddc_sync5_66;
       array6[66] = &hf_openhpsdr_e_ddcc_ddc_sync6_66;
       array7[66] = &hf_openhpsdr_e_ddcc_ddc_sync7_66;
       array0[67] = &hf_openhpsdr_e_ddcc_ddc_sync0_67;
       array1[67] = &hf_openhpsdr_e_ddcc_ddc_sync1_67;
       array2[67] = &hf_openhpsdr_e_ddcc_ddc_sync2_67;
       array3[67] = &hf_openhpsdr_e_ddcc_ddc_sync3_67;
       array4[67] = &hf_openhpsdr_e_ddcc_ddc_sync4_67;
       array5[67] = &hf_openhpsdr_e_ddcc_ddc_sync5_67;
       array6[67] = &hf_openhpsdr_e_ddcc_ddc_sync6_67;
       array7[67] = &hf_openhpsdr_e_ddcc_ddc_sync7_67;
       array0[68] = &hf_openhpsdr_e_ddcc_ddc_sync0_68;
       array1[68] = &hf_openhpsdr_e_ddcc_ddc_sync1_68;
       array2[68] = &hf_openhpsdr_e_ddcc_ddc_sync2_68;
       array3[68] = &hf_openhpsdr_e_ddcc_ddc_sync3_68;
       array4[68] = &hf_openhpsdr_e_ddcc_ddc_sync4_68;
       array5[68] = &hf_openhpsdr_e_ddcc_ddc_sync5_68;
       array6[68] = &hf_openhpsdr_e_ddcc_ddc_sync6_68;
       array7[68] = &hf_openhpsdr_e_ddcc_ddc_sync7_68;
       array0[69] = &hf_openhpsdr_e_ddcc_ddc_sync0_69;
       array1[69] = &hf_openhpsdr_e_ddcc_ddc_sync1_69;
       array2[69] = &hf_openhpsdr_e_ddcc_ddc_sync2_69;
       array3[69] = &hf_openhpsdr_e_ddcc_ddc_sync3_69;
       array4[69] = &hf_openhpsdr_e_ddcc_ddc_sync4_69;
       array5[69] = &hf_openhpsdr_e_ddcc_ddc_sync5_69;
       array6[69] = &hf_openhpsdr_e_ddcc_ddc_sync6_69;
       array7[69] = &hf_openhpsdr_e_ddcc_ddc_sync7_69;
       array0[70] = &hf_openhpsdr_e_ddcc_ddc_sync0_70;
       array1[70] = &hf_openhpsdr_e_ddcc_ddc_sync1_70;
       array2[70] = &hf_openhpsdr_e_ddcc_ddc_sync2_70;
       array3[70] = &hf_openhpsdr_e_ddcc_ddc_sync3_70;
       array4[70] = &hf_openhpsdr_e_ddcc_ddc_sync4_70;
       array5[70] = &hf_openhpsdr_e_ddcc_ddc_sync5_70;
       array6[70] = &hf_openhpsdr_e_ddcc_ddc_sync6_70;
       array7[70] = &hf_openhpsdr_e_ddcc_ddc_sync7_70;
       array0[71] = &hf_openhpsdr_e_ddcc_ddc_sync0_71;
       array1[71] = &hf_openhpsdr_e_ddcc_ddc_sync1_71;
       array2[71] = &hf_openhpsdr_e_ddcc_ddc_sync2_71;
       array3[71] = &hf_openhpsdr_e_ddcc_ddc_sync3_71;
       array4[71] = &hf_openhpsdr_e_ddcc_ddc_sync4_71;
       array5[71] = &hf_openhpsdr_e_ddcc_ddc_sync5_71;
       array6[71] = &hf_openhpsdr_e_ddcc_ddc_sync6_71;
       array7[71] = &hf_openhpsdr_e_ddcc_ddc_sync7_71;
       array0[72] = &hf_openhpsdr_e_ddcc_ddc_sync0_72;
       array1[72] = &hf_openhpsdr_e_ddcc_ddc_sync1_72;
       array2[72] = &hf_openhpsdr_e_ddcc_ddc_sync2_72;
       array3[72] = &hf_openhpsdr_e_ddcc_ddc_sync3_72;
       array4[72] = &hf_openhpsdr_e_ddcc_ddc_sync4_72;
       array5[72] = &hf_openhpsdr_e_ddcc_ddc_sync5_72;
       array6[72] = &hf_openhpsdr_e_ddcc_ddc_sync6_72;
       array7[72] = &hf_openhpsdr_e_ddcc_ddc_sync7_72;
       array0[73] = &hf_openhpsdr_e_ddcc_ddc_sync0_73;
       array1[73] = &hf_openhpsdr_e_ddcc_ddc_sync1_73;
       array2[73] = &hf_openhpsdr_e_ddcc_ddc_sync2_73;
       array3[73] = &hf_openhpsdr_e_ddcc_ddc_sync3_73;
       array4[73] = &hf_openhpsdr_e_ddcc_ddc_sync4_73;
       array5[73] = &hf_openhpsdr_e_ddcc_ddc_sync5_73;
       array6[73] = &hf_openhpsdr_e_ddcc_ddc_sync6_73;
       array7[73] = &hf_openhpsdr_e_ddcc_ddc_sync7_73;
       array0[74] = &hf_openhpsdr_e_ddcc_ddc_sync0_74;
       array1[74] = &hf_openhpsdr_e_ddcc_ddc_sync1_74;
       array2[74] = &hf_openhpsdr_e_ddcc_ddc_sync2_74;
       array3[74] = &hf_openhpsdr_e_ddcc_ddc_sync3_74;
       array4[74] = &hf_openhpsdr_e_ddcc_ddc_sync4_74;
       array5[74] = &hf_openhpsdr_e_ddcc_ddc_sync5_74;
       array6[74] = &hf_openhpsdr_e_ddcc_ddc_sync6_74;
       array7[74] = &hf_openhpsdr_e_ddcc_ddc_sync7_74;
       array0[75] = &hf_openhpsdr_e_ddcc_ddc_sync0_75;
       array1[75] = &hf_openhpsdr_e_ddcc_ddc_sync1_75;
       array2[75] = &hf_openhpsdr_e_ddcc_ddc_sync2_75;
       array3[75] = &hf_openhpsdr_e_ddcc_ddc_sync3_75;
       array4[75] = &hf_openhpsdr_e_ddcc_ddc_sync4_75;
       array5[75] = &hf_openhpsdr_e_ddcc_ddc_sync5_75;
       array6[75] = &hf_openhpsdr_e_ddcc_ddc_sync6_75;
       array7[75] = &hf_openhpsdr_e_ddcc_ddc_sync7_75;
       array0[76] = &hf_openhpsdr_e_ddcc_ddc_sync0_76;
       array1[76] = &hf_openhpsdr_e_ddcc_ddc_sync1_76;
       array2[76] = &hf_openhpsdr_e_ddcc_ddc_sync2_76;
       array3[76] = &hf_openhpsdr_e_ddcc_ddc_sync3_76;
       array4[76] = &hf_openhpsdr_e_ddcc_ddc_sync4_76;
       array5[76] = &hf_openhpsdr_e_ddcc_ddc_sync5_76;
       array6[76] = &hf_openhpsdr_e_ddcc_ddc_sync6_76;
       array7[76] = &hf_openhpsdr_e_ddcc_ddc_sync7_76;
       array0[77] = &hf_openhpsdr_e_ddcc_ddc_sync0_77;
       array1[77] = &hf_openhpsdr_e_ddcc_ddc_sync1_77;
       array2[77] = &hf_openhpsdr_e_ddcc_ddc_sync2_77;
       array3[77] = &hf_openhpsdr_e_ddcc_ddc_sync3_77;
       array4[77] = &hf_openhpsdr_e_ddcc_ddc_sync4_77;
       array5[77] = &hf_openhpsdr_e_ddcc_ddc_sync5_77;
       array6[77] = &hf_openhpsdr_e_ddcc_ddc_sync6_77;
       array7[77] = &hf_openhpsdr_e_ddcc_ddc_sync7_77;
       array0[78] = &hf_openhpsdr_e_ddcc_ddc_sync0_78;
       array1[78] = &hf_openhpsdr_e_ddcc_ddc_sync1_78;
       array2[78] = &hf_openhpsdr_e_ddcc_ddc_sync2_78;
       array3[78] = &hf_openhpsdr_e_ddcc_ddc_sync3_78;
       array4[78] = &hf_openhpsdr_e_ddcc_ddc_sync4_78;
       array5[78] = &hf_openhpsdr_e_ddcc_ddc_sync5_78;
       array6[78] = &hf_openhpsdr_e_ddcc_ddc_sync6_78;
       array7[78] = &hf_openhpsdr_e_ddcc_ddc_sync7_78;
       array0[79] = &hf_openhpsdr_e_ddcc_ddc_sync0_79;
       array1[79] = &hf_openhpsdr_e_ddcc_ddc_sync1_79;
       array2[79] = &hf_openhpsdr_e_ddcc_ddc_sync2_79;
       array3[79] = &hf_openhpsdr_e_ddcc_ddc_sync3_79;
       array4[79] = &hf_openhpsdr_e_ddcc_ddc_sync4_79;
       array5[79] = &hf_openhpsdr_e_ddcc_ddc_sync5_79;
       array6[79] = &hf_openhpsdr_e_ddcc_ddc_sync6_79;
       array7[79] = &hf_openhpsdr_e_ddcc_ddc_sync7_79;

       sync_tree_ddcc_item = proto_tree_add_uint_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_sync_sub, 
           tvb, offset,80, value,"DDC Synchronization"); 
       openhpsdr_e_ddcc_sync_tree = proto_item_add_subtree(sync_tree_ddcc_item,ett_openhpsdr_e_ddcc_sync);

       for (i=0;i<=79;i++) {

       value = tvb_get_guint8(tvb, offset);
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array0[i], tvb,offset, 1, value);
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array1[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array2[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array3[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array4[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array5[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array6[i], tvb,offset, 1, value); 
           proto_tree_add_boolean(openhpsdr_e_ddcc_sync_tree, *array7[i], tvb,offset, 1, value); 
           offset += 1; 
       
       }

       mux_tree_ddcc_item = proto_tree_add_uint_format(openhpsdr_e_ddcc_tree, hf_openhpsdr_e_ddcc_mux_sub, 
           tvb, offset,1, value,"DDC Multiplex"); 
       openhpsdr_e_ddcc_mux_tree = proto_item_add_subtree(mux_tree_ddcc_item,ett_openhpsdr_e_ddcc_mux);

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux1, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux2, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux3, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux4, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux5, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux6, tvb,offset, 1, value); 
       proto_tree_add_boolean(openhpsdr_e_ddcc_mux_tree, hf_openhpsdr_e_ddcc_ddc_mux7, tvb,offset, 1, value); 
       offset += 1; 

       cr_check_length(tvb,pinfo,tree,offset);



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
   guint8 value = -1;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR HPS");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_hps_item = NULL;

       proto_tree *openhpsdr_e_hps_tree = NULL;

       proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_hps_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_hps_tree = proto_item_add_subtree(parent_tree_hps_item, ett_openhpsdr_e_hps);

       proto_tree_add_string_format(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - High Priority Status");

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_ptt, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_dot, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_dash, tvb,offset, 1, value);

       append_text_item = proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_empty, tvb,offset, 1, value);
       proto_item_append_text(append_text_item," Not Used");
  
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_pll, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fifo_empty, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fifo_full, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc0_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc1_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc2_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc3_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc4_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc5_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc6_ol, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_adc7_ol, tvb,offset, 1, value);
       offset += 1;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_ex_power0, tvb,offset, 2, ENC_BIG_ENDIAN);
// Add Exciter Power Calculation 
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_ex_power1, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_ex_power2, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_ex_power3, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fp_alex0, tvb,offset, 2, ENC_BIG_ENDIAN);
// Add Forward Power Calculation 
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fp_alex1, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fp_alex2, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_fp_alex3, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_rp_alex0, tvb,offset, 2, ENC_BIG_ENDIAN);
// Add Reverse Power Calculation 
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_rp_alex1, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_rp_alex2, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_rp_alex3, tvb,offset, 2, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Reserved for Future Use");
       offset += 2;

       proto_tree_add_string_format(openhpsdr_e_hps_tree,hf_openhpsdr_e_reserved ,tvb,offset,19,placehold,
           "Reserved for Future Use: 19 Bytes");
       offset += 19;
 
       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_supp_vol, tvb,offset, 2, ENC_BIG_ENDIAN);
// Add Supply Volts Calculation 
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_adc3, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_adc2, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_adc1, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       proto_tree_add_item(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_adc0, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic4, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic6, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hps_tree, hf_openhpsdr_e_hps_user_logic7, tvb,offset, 1, value);
       offset += 1;

       cr_check_length(tvb,pinfo,tree,offset);

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
   guint8 value = -1;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DUCC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ducc_item = NULL;

       proto_tree *openhpsdr_e_ducc_tree = NULL;

       proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_ducc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ducc_tree = proto_item_add_subtree(parent_tree_ducc_item, ett_openhpsdr_e_ducc);

       proto_tree_add_string_format(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DUC Command");

       proto_tree_add_item(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_dac_num, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_eer, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_cw, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_rev_cw, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_iambic, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_sidetone, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_cw_mode_b, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_cw_st_char_space, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_cw_breakin, tvb,offset, 1, value);
       offset += 1;

       proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_cw_sidetone_level, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_cw_sidetone_freq, tvb,offset, 2,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 2;

       append_text_item =  proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_cw_keyer_speed, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," WPM");
       offset += 1;

       proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_cw_keyer_weight, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       append_text_item =  proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_cw_hang_delay, tvb,offset, 2,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," mS");
       offset += 2;

       append_text_item =  proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_rf_delay, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," mS");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_duc0_sample, tvb,offset, 2,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," ksps");
       offset += 2;

       append_text_item = proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_duc0_bits, tvb,offset, 1, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," bits");
       offset += 1;

       proto_tree_add_string_format(openhpsdr_e_ducc_tree,hf_openhpsdr_e_reserved ,tvb,offset,9,placehold,
           "Reserved for Future Use: 9 Bytes");
       offset += 9;

       append_text_item = proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_duc0_phase_shift, tvb,offset, 2,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," degress - Future Use");
       offset += 2;

       proto_tree_add_string_format(openhpsdr_e_ducc_tree,hf_openhpsdr_e_reserved ,tvb,offset,22,placehold,
           "Reserved for Future Use: 22 Bytes");
       offset += 22;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_line_in, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_mic_boost, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_orion_mic_ptt, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_orion_mic_ring_tip, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_ducc_tree, hf_openhpsdr_e_ducc_orion_mic_bias, tvb,offset, 1, value);
       offset += 1;

       proto_tree_add_string_format(openhpsdr_e_ducc_tree,hf_openhpsdr_e_reserved ,tvb,offset,7,placehold,
           "Reserved for Future Use: 7 Bytes");
       offset += 7;

       proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_line_in_gain, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_ducc_tree,hf_openhpsdr_e_ducc_attn_adc0_duc0, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       cr_check_length(tvb,pinfo,tree,offset);

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

   int idx = 0;

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

       proto_tree_add_string_format(openhpsdr_e_micl_tree, hf_openhpsdr_e_micl_banner,tvb,offset,0,placehold,
           "Assuming 720 by 16 bit samples"); 
     
       // for idx 0 to 719
       for ( idx=0; idx <= 719; idx++) {
           proto_tree_add_string_format(openhpsdr_e_micl_tree, hf_openhpsdr_e_micl_separator, tvb, offset, 0, placehold,
              "----------------------------------------------------------");
      
           proto_tree_add_uint_format(openhpsdr_e_micl_tree, hf_openhpsdr_e_micl_sample_idx, tvb, offset, 0, idx,"Sample: %d",idx); 
 
           proto_tree_add_item(openhpsdr_e_micl_tree,hf_openhpsdr_e_micl_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
           offset += 2;

// Add calculated sample value. 
       }
       
       
       cr_check_length(tvb,pinfo,tree,offset);

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
   guint8 value = -1;

   int *array0[80];
   int i = 0 ;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR HPC");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_hpc_item = NULL;
       proto_item *ddc_fp_tree_hpc_item = NULL;
       proto_item *alex0_tree_hpc_item = NULL;
 
       proto_tree *openhpsdr_e_hpc_tree = NULL;
       proto_tree *openhpsdr_e_hpc_ddc_fp_tree = NULL;
       proto_tree *openhpsdr_e_hpc_alex0_tree = NULL;

       proto_item *append_text_item = NULL;
       //proto_item *ei_item = NULL;

       parent_tree_hpc_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_hpc_tree = proto_item_add_subtree(parent_tree_hpc_item, ett_openhpsdr_e_hpc);

       proto_tree_add_string_format(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - High Priority Command");

       proto_tree_add_item(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_run, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_ptt0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_ptt1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_ptt2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_ptt3, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_cwx0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_dot, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_dash, tvb,offset, 1, value);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_cwx1, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_cwx2, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_cwx3, tvb,offset, 1,
           ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       array0[0] = &hf_openhpsdr_e_hpc_freq_phase_ddc0;
       array0[1] = &hf_openhpsdr_e_hpc_freq_phase_ddc1;
       array0[2] = &hf_openhpsdr_e_hpc_freq_phase_ddc2;
       array0[3] = &hf_openhpsdr_e_hpc_freq_phase_ddc3;
       array0[4] = &hf_openhpsdr_e_hpc_freq_phase_ddc4;
       array0[5] = &hf_openhpsdr_e_hpc_freq_phase_ddc5;
       array0[6] = &hf_openhpsdr_e_hpc_freq_phase_ddc6;
       array0[7] = &hf_openhpsdr_e_hpc_freq_phase_ddc7;
       array0[8] = &hf_openhpsdr_e_hpc_freq_phase_ddc8;
       array0[9] = &hf_openhpsdr_e_hpc_freq_phase_ddc9;
       array0[10] = &hf_openhpsdr_e_hpc_freq_phase_ddc10;
       array0[11] = &hf_openhpsdr_e_hpc_freq_phase_ddc11;
       array0[12] = &hf_openhpsdr_e_hpc_freq_phase_ddc12;
       array0[13] = &hf_openhpsdr_e_hpc_freq_phase_ddc13;
       array0[14] = &hf_openhpsdr_e_hpc_freq_phase_ddc14;
       array0[15] = &hf_openhpsdr_e_hpc_freq_phase_ddc15;
       array0[16] = &hf_openhpsdr_e_hpc_freq_phase_ddc16;
       array0[17] = &hf_openhpsdr_e_hpc_freq_phase_ddc17;
       array0[18] = &hf_openhpsdr_e_hpc_freq_phase_ddc18;
       array0[19] = &hf_openhpsdr_e_hpc_freq_phase_ddc19;
       array0[20] = &hf_openhpsdr_e_hpc_freq_phase_ddc20;
       array0[21] = &hf_openhpsdr_e_hpc_freq_phase_ddc21;
       array0[22] = &hf_openhpsdr_e_hpc_freq_phase_ddc22;
       array0[23] = &hf_openhpsdr_e_hpc_freq_phase_ddc23;
       array0[24] = &hf_openhpsdr_e_hpc_freq_phase_ddc24;
       array0[25] = &hf_openhpsdr_e_hpc_freq_phase_ddc25;
       array0[26] = &hf_openhpsdr_e_hpc_freq_phase_ddc26;
       array0[27] = &hf_openhpsdr_e_hpc_freq_phase_ddc27;
       array0[28] = &hf_openhpsdr_e_hpc_freq_phase_ddc28;
       array0[29] = &hf_openhpsdr_e_hpc_freq_phase_ddc29;
       array0[30] = &hf_openhpsdr_e_hpc_freq_phase_ddc30;
       array0[31] = &hf_openhpsdr_e_hpc_freq_phase_ddc31;
       array0[32] = &hf_openhpsdr_e_hpc_freq_phase_ddc32;
       array0[33] = &hf_openhpsdr_e_hpc_freq_phase_ddc33;
       array0[34] = &hf_openhpsdr_e_hpc_freq_phase_ddc34;
       array0[35] = &hf_openhpsdr_e_hpc_freq_phase_ddc35;
       array0[36] = &hf_openhpsdr_e_hpc_freq_phase_ddc36;
       array0[37] = &hf_openhpsdr_e_hpc_freq_phase_ddc37;
       array0[38] = &hf_openhpsdr_e_hpc_freq_phase_ddc38;
       array0[39] = &hf_openhpsdr_e_hpc_freq_phase_ddc39;
       array0[40] = &hf_openhpsdr_e_hpc_freq_phase_ddc40;
       array0[41] = &hf_openhpsdr_e_hpc_freq_phase_ddc41;
       array0[42] = &hf_openhpsdr_e_hpc_freq_phase_ddc42;
       array0[43] = &hf_openhpsdr_e_hpc_freq_phase_ddc43;
       array0[44] = &hf_openhpsdr_e_hpc_freq_phase_ddc44;
       array0[45] = &hf_openhpsdr_e_hpc_freq_phase_ddc45;
       array0[46] = &hf_openhpsdr_e_hpc_freq_phase_ddc46;
       array0[47] = &hf_openhpsdr_e_hpc_freq_phase_ddc47;
       array0[48] = &hf_openhpsdr_e_hpc_freq_phase_ddc48;
       array0[49] = &hf_openhpsdr_e_hpc_freq_phase_ddc49;
       array0[50] = &hf_openhpsdr_e_hpc_freq_phase_ddc50;
       array0[51] = &hf_openhpsdr_e_hpc_freq_phase_ddc51;
       array0[52] = &hf_openhpsdr_e_hpc_freq_phase_ddc52;
       array0[53] = &hf_openhpsdr_e_hpc_freq_phase_ddc53;
       array0[54] = &hf_openhpsdr_e_hpc_freq_phase_ddc54;
       array0[55] = &hf_openhpsdr_e_hpc_freq_phase_ddc55;
       array0[56] = &hf_openhpsdr_e_hpc_freq_phase_ddc56;
       array0[57] = &hf_openhpsdr_e_hpc_freq_phase_ddc57;
       array0[58] = &hf_openhpsdr_e_hpc_freq_phase_ddc58;
       array0[59] = &hf_openhpsdr_e_hpc_freq_phase_ddc59;
       array0[60] = &hf_openhpsdr_e_hpc_freq_phase_ddc60;
       array0[61] = &hf_openhpsdr_e_hpc_freq_phase_ddc61;
       array0[62] = &hf_openhpsdr_e_hpc_freq_phase_ddc62;
       array0[63] = &hf_openhpsdr_e_hpc_freq_phase_ddc63;
       array0[64] = &hf_openhpsdr_e_hpc_freq_phase_ddc64;
       array0[65] = &hf_openhpsdr_e_hpc_freq_phase_ddc65;
       array0[66] = &hf_openhpsdr_e_hpc_freq_phase_ddc66;
       array0[67] = &hf_openhpsdr_e_hpc_freq_phase_ddc67;
       array0[68] = &hf_openhpsdr_e_hpc_freq_phase_ddc68;
       array0[69] = &hf_openhpsdr_e_hpc_freq_phase_ddc69;
       array0[70] = &hf_openhpsdr_e_hpc_freq_phase_ddc70;
       array0[71] = &hf_openhpsdr_e_hpc_freq_phase_ddc71;
       array0[72] = &hf_openhpsdr_e_hpc_freq_phase_ddc72;
       array0[73] = &hf_openhpsdr_e_hpc_freq_phase_ddc73;
       array0[74] = &hf_openhpsdr_e_hpc_freq_phase_ddc74;
       array0[75] = &hf_openhpsdr_e_hpc_freq_phase_ddc75;
       array0[76] = &hf_openhpsdr_e_hpc_freq_phase_ddc76;
       array0[77] = &hf_openhpsdr_e_hpc_freq_phase_ddc77;
       array0[78] = &hf_openhpsdr_e_hpc_freq_phase_ddc78;
       array0[79] = &hf_openhpsdr_e_hpc_freq_phase_ddc79;

       ddc_fp_tree_hpc_item = proto_tree_add_uint_format(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_ddc_fp_sub,
           tvb, offset,320, value,"DDC Frequency / Phase Word");
       openhpsdr_e_hpc_ddc_fp_tree = proto_item_add_subtree(ddc_fp_tree_hpc_item,ett_openhpsdr_e_hpc_ddc_fp);

       for (i=0;i<=79;i++) {
           proto_tree_add_item(openhpsdr_e_hpc_ddc_fp_tree,*array0[i], tvb,offset, 4,ENC_BIG_ENDIAN);
           offset += 4; 
       }

       proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_freq_phase_duc0, tvb,offset, 4,ENC_BIG_ENDIAN);
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_freq_phase_duc1, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_freq_phase_duc2, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_freq_phase_duc3, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_drive_duc0, tvb,offset, 1,ENC_BIG_ENDIAN);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_drive_duc1, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_drive_duc2, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_drive_duc3, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 1;

       proto_tree_add_string_format(openhpsdr_e_hpc_tree,hf_openhpsdr_e_reserved ,tvb,offset,1052,placehold,
           "Reserved for Future Use: 1052 Bytes");
       offset += 1052;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col4, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col6, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_open_col7, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_db9_out1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_db9_out2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_db9_out3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_db9_out4, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_merc_att1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_merc_att2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_merc_att3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_merc_att4, tvb,offset, 1, value);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex7, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex6, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex5, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex4, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex3, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex2, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_alex1, tvb,offset, 4,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Future Use");
       offset += 4;

       alex0_tree_hpc_item = proto_tree_add_uint_format(openhpsdr_e_hpc_tree, hf_openhpsdr_e_hpc_alex0_sub,
           tvb, offset,4, value,"Alex 0");
       openhpsdr_e_hpc_alex0_tree = proto_item_add_subtree(alex0_tree_hpc_item,ett_openhpsdr_e_hpc_alex0);

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_17_15, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_12_10, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_bypass, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_red_led1, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_tx_rx, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ant3, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ant2, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ant1, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_160, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_80, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_60_40, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_lpf_30_20, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_yel_led1, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_red_led0, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_att_10, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_att_20, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hf_bypass, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ddc1_out, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ddc1_in, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ddc2_in, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_ddc_xvtr_in, tvb,offset, 1, value);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hpf_1_5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hpf_6_5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hpf_9_5, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_6m_amp, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hpf_20, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_hpf_13, tvb,offset, 1, value);
       proto_tree_add_boolean(openhpsdr_e_hpc_alex0_tree, hf_openhpsdr_e_hpc_alex0_yel_led0, tvb,offset, 1, value);
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att7, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att6, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att5, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att4, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att3, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att2, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB - Future Use");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att1, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB");
       offset += 1;

       append_text_item = proto_tree_add_item(openhpsdr_e_hpc_tree,hf_openhpsdr_e_hpc_att0, tvb,offset, 1,ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB");
       offset += 1;

       cr_check_length(tvb,pinfo,tree,offset);

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

   long int adc_num = -1;     
   int idx = 0;

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

       // Calulate which ADC the Data is from.
       if ( pinfo->srcport >= HPSDR_E_BPORT_WB_DAT && pinfo->srcport <= (guint16)(HPSDR_E_BPORT_WB_DAT + 7) ) { // Default port

           adc_num = pinfo->srcport - (guint16)HPSDR_E_BPORT_WB_DAT; 

       } else if ( pinfo->srcport >= openhpsdr_e_cr_wbd_base_port &&
               pinfo->srcport <= (guint16)(openhpsdr_e_cr_wbd_base_port + 7) ) {  // Non-default port

           adc_num = pinfo->srcport - openhpsdr_e_cr_wbd_base_port;

       }

       proto_tree_add_uint_format(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_adc, tvb, offset, 0, adc_num,
           "WBD from ADC: %ld  - Calculated from source port number",adc_num); 

       proto_tree_add_string_format(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_banner,tvb,offset,0,placehold,
           "Assuming 512 by 16 bit samples");

       for ( idx=0; idx <= 511; idx++) {
           proto_tree_add_string_format(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_separator, tvb, offset, 0, placehold,
              "----------------------------------------------------------");

           proto_tree_add_uint_format(openhpsdr_e_wbd_tree, hf_openhpsdr_e_wbd_sample_idx, tvb, offset, 0, idx,
               "Sample: %d",idx); 
 
           proto_tree_add_item(openhpsdr_e_wbd_tree,hf_openhpsdr_e_wbd_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
           offset += 2;

       }

       cr_check_length(tvb,pinfo,tree,offset);

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

   int idx = 0;
   
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

       proto_tree_add_string_format(openhpsdr_e_ddca_tree, hf_openhpsdr_e_ddca_banner,tvb,offset,0,placehold,
           "Assuming default 360 by 16 bits left and right samples");

       for ( idx=0; idx <= 359; idx++) {
           proto_tree_add_string_format(openhpsdr_e_ddca_tree, hf_openhpsdr_e_ddca_separator, tvb, offset, 0, placehold,
              "----------------------------------------------------------");

           proto_tree_add_uint_format(openhpsdr_e_ddca_tree, hf_openhpsdr_e_ddca_sample_idx, tvb, offset, 0, idx,
               "Sample: %d",idx); 
 
           proto_tree_add_item(openhpsdr_e_ddca_tree,hf_openhpsdr_e_ddca_l_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
           offset += 2;

           proto_tree_add_item(openhpsdr_e_ddca_tree,hf_openhpsdr_e_ddca_r_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
           offset += 2;

       }

       cr_check_length(tvb,pinfo,tree,offset);

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

   long int duc_num = -1;
   int idx = 0;

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

       // Get the DUC the data is for  
       if ( pinfo->destport >= HPSDR_E_BPORT_DUC_IQ && pinfo->destport <= (guint16)(HPSDR_E_BPORT_DUC_IQ + 7)  ) {
       // Default Port 
 
           duc_num = pinfo->destport - (guint16)HPSDR_E_BPORT_DUC_IQ; 

       } else if ( pinfo->destport >= openhpsdr_e_cr_duciq_base_port && 
               pinfo->destport <= (guint16)(openhpsdr_e_cr_duciq_base_port + 7) ) { // Non-default port 

           duc_num = pinfo->destport - openhpsdr_e_cr_duciq_base_port;

       }

       proto_tree_add_uint_format(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_duc, tvb, offset, 0, duc_num,
           "Data for DUC: %ld  - Calculated from destination port number",duc_num); 

       proto_tree_add_string_format(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_banner,tvb,offset,0,placehold,
           "Assuming default 240 by 24 bit I and Q samples");

       for ( idx=0; idx <= 239; idx++) {
           proto_tree_add_string_format(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_separator, tvb, offset, 0, placehold,
              "----------------------------------------------------------");

           proto_tree_add_uint_format(openhpsdr_e_duciq_tree, hf_openhpsdr_e_duciq_sample_idx, tvb, offset, 0, idx,
               "Sample: %d",idx); 

           proto_tree_add_item(openhpsdr_e_duciq_tree,hf_openhpsdr_e_duciq_i_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
           offset += 3;

           proto_tree_add_item(openhpsdr_e_duciq_tree,hf_openhpsdr_e_duciq_q_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
           offset += 3;

       }

       cr_check_length(tvb,pinfo,tree,offset);

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
 
   guint16 sample_bits = -1; 
   guint16 samples_num = -1; 

   long int ddc_num = -1;
   long int total_bytes = -1;
   int idx = 0;

   const char *placehold = NULL ;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "openHPSDR DDCIQ");
   // Clear out the info column
   col_clear(pinfo->cinfo,COL_INFO);

   if (tree) {
       proto_item *parent_tree_ddciq_item = NULL;

       proto_tree *openhpsdr_e_ddciq_tree = NULL;

       //proto_item *append_text_item = NULL;
       proto_item *ei_item = NULL;

       parent_tree_ddciq_item = proto_tree_add_item(tree, proto_openhpsdr_e, tvb, 0, -1, ENC_NA);
       openhpsdr_e_ddciq_tree = proto_item_add_subtree(parent_tree_ddciq_item, ett_openhpsdr_e_ddciq);

       proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_banner,tvb,offset,0,placehold,
           "openHPSDR Ethernet - DDC I&Q Data");

       proto_tree_add_item(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;

       // Get the DDC the Data is from
       if ( pinfo->srcport >= HPSDR_E_BPORT_DDC_IQ && pinfo->srcport <= (guint16)(HPSDR_E_BPORT_DDC_IQ + 79)  ) {
       // Default Port

           ddc_num = pinfo->srcport - (guint16)HPSDR_E_BPORT_DDC_IQ;

       } else if ( pinfo->srcport >= openhpsdr_e_cr_ddciq_base_port && 
               pinfo->srcport <= (guint16)(openhpsdr_e_cr_ddciq_base_port + 79) ) { // Non-default port

           ddc_num = pinfo->srcport - openhpsdr_e_cr_ddciq_base_port;

       }

       proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_ddc, tvb, offset, 0, ddc_num,
           "Data from DDC      : %ld - Calculated from source port number",ddc_num); 

      
       proto_tree_add_item(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_time_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
       offset += 8;

       sample_bits = tvb_get_guint16(tvb, offset,2);
       proto_tree_add_item(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       samples_num = tvb_get_guint16(tvb, offset,2);
       proto_tree_add_item(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_samples_per_frame, tvb, offset, 2, ENC_BIG_ENDIAN);
       offset += 2;


       // 42 bytes for ISO layers 1 to 3: Ethernet, IPv4, UDP
       //    : 14 ( 0-13) bytes Ethernet
       //    : 20 (14-33) bytes IPv4
       //    :  8 (34-41) UDP   
       // 16 (42-57) bytes for DDC I&Q before samples.
       // 16 + 42 = 58 bytes
       // The sample bytes are (I bytes + Q bytes) times number of samples.
       // 58 bytes + samples must be less then or equal to 1500 bytes.
       // 1500 is the standard maximum transmission unit (MTU) for Ethernet v2 frames.
       // Internet Protocol (IP) over Ethernet uses Ethernet v2 frames.  
       total_bytes = (long int) ( ( ((sample_bits / 8)*2) * samples_num ) + 58);

       proto_tree_add_uint_format(openhpsdr_e_ddciq_tree,
           hf_openhpsdr_e_ddciq_ethernet_frame_size, tvb, offset, 0, total_bytes, 
           "Ethernet Frame Size: %ld - Calculated, not in datagram", total_bytes);              


       if (openhpsdr_e_ddciq_mtu_check) {
 
           if ( total_bytes > 1500) {
               ei_item = proto_tree_add_string_format(tree, hf_openhpsdr_e_cr_ei, tvb, 
                    offset, total_bytes, placehold,"Larger then MTU");
               expert_add_info_format(pinfo,ei_item,&ei_ddciq_larger_then_mtu,
           "Ethernet frame will be %ld bytes larger them Ethernet MTU.",total_bytes-1500);

           }

       }

       proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_banner,tvb,offset,0,placehold,
           "Assuming no synchronous or multiplexed DDC");

       if ( sample_bits == 0x0008) {  // 8 bit samples

           for ( idx=0; idx <= (int)samples_num-1; idx++) {
               proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_separator, tvb, offset, 0, placehold,
                  "----------------------------------------------------------");

               proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_idx, tvb, offset, 0, idx,
                  "Sample: %d",idx); 

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_8b_i_sample, tvb,offset, 1, ENC_BIG_ENDIAN);
               offset += 1;

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_8b_q_sample, tvb,offset, 1, ENC_BIG_ENDIAN);
               offset += 1;
           }
 
       } else if ( sample_bits == 0x0010) {  // 16 bit samples

           for ( idx=0; idx <= (int)samples_num-1; idx++) {
               proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_separator, tvb, offset, 0, placehold,
                  "----------------------------------------------------------");

               proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_idx, tvb, offset, 0, idx,
                  "Sample: %d",idx); 

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_16b_i_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
               offset += 2;

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_16b_q_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
               offset += 2;
           }

       } else if ( sample_bits == 0x0018) {  // 24 bit samples

           for ( idx=0; idx <= (int)samples_num-1; idx++) {
               proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_separator, tvb, offset, 0, placehold,
                  "----------------------------------------------------------");

               proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_idx, tvb, offset, 0, idx,
                  "Sample: %d",idx); 

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_24b_i_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
               offset += 3;

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_24b_q_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
               offset += 3;
           }

       } else if ( sample_bits == 0x0020) {  // 32 bit samples {

           for ( idx=0; idx <= (int)samples_num-1; idx++) {
               proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_separator, tvb, offset, 0, placehold,
                  "----------------------------------------------------------");

               proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_idx, tvb, offset, 0, idx,
                  "Sample: %d",idx); 

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_32b_i_sample, tvb,offset, 4, ENC_BIG_ENDIAN);
               offset += 4;

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_32b_q_sample, tvb,offset, 4, ENC_BIG_ENDIAN);
               offset += 4;
           }
       
       } else {

           proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_banner,tvb,offset,0,placehold,
               "Unsupported bits per sample - Assuming default 240 by 24 bit samples"); 
        
           for ( idx=0; idx <= 239; idx++) {
               proto_tree_add_string_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_separator, tvb, offset, 0, placehold,
                  "----------------------------------------------------------");

               proto_tree_add_uint_format(openhpsdr_e_ddciq_tree, hf_openhpsdr_e_ddciq_sample_idx, tvb, offset, 0, idx,
                  "Sample: %d",idx); 

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_24b_i_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
               offset += 3;

               proto_tree_add_item(openhpsdr_e_ddciq_tree,hf_openhpsdr_e_ddciq_24b_q_sample, tvb,offset, 3, ENC_BIG_ENDIAN);
               offset += 3;
           }

       }

       cr_check_length(tvb,pinfo,tree,offset);

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

   int idx = 0;
 
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

       if ( pinfo->destport == openhpsdr_e_cr_mem_host_port ) {
 
           proto_tree_add_string_format(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_banner,tvb,offset,0,placehold,
               "Memory Data from Host");

       } else if ( pinfo->srcport == openhpsdr_e_cr_mem_hw_port ) {

           proto_tree_add_string_format(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_banner,tvb,offset,0,placehold,
               "Memory Data from Hardware");
       }

       proto_tree_add_item(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_sequence_num, tvb,offset, 4, ENC_BIG_ENDIAN); 
       offset += 4;


       for ( idx=0; idx <= 239; idx++) {
           proto_tree_add_string_format(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_separator, tvb, offset, 0, placehold,
              "----------------------------------------------------------");

           proto_tree_add_uint_format(openhpsdr_e_mem_tree, hf_openhpsdr_e_mem_idx, tvb, offset, 0, idx,
               "Index: %d",idx); 

           proto_tree_add_item(openhpsdr_e_mem_tree,hf_openhpsdr_e_mem_address, tvb,offset, 2, ENC_BIG_ENDIAN);
           offset += 2;

           proto_tree_add_item(openhpsdr_e_mem_tree,hf_openhpsdr_e_mem_data, tvb,offset, 4, ENC_BIG_ENDIAN);
           offset += 4;

       }

       cr_check_length(tvb,pinfo,tree,offset);

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

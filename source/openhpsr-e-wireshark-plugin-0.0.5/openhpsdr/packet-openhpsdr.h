/* packet-openhpsdr.h  
 * Header file for the OpenHPSDR Ethernet protocol packet disassembly
 *
 * This file is part of the OpenHPSDR Plug-in for Wireshark.
 * By Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
 * Copyright 2017 Matthew J. Wolf
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
 */

// UDP PORTS 
#define HPSDR_E_PORT_COM_REP 1024 // COMMAND REPLY PROTOCOL 
#define HPSDR_E_PORT_DDC_COM 1025 // DCC COMMAND PROTOCOL    -DEST   PORT (SOURCE HOST)
#define HPSDR_E_PORT_HP_STAT 1025 // HIGH PRIORITY STATUS    -SOURCE PORT (SOURCE HARDWARE)
#define HPSDR_E_PORT_DUC_COM 1026 // DUC COMMAND PROTOCOL    -DEST   PORT (SOURCE HOST)
#define HPSDR_E_PORT_MICL_S  1026 // MIC / LINE SAMPLES      -SOURCE PORT (SOURCE HARDWARE)
#define HPSDR_E_PORT_HP_COM  1027 // HIGH PRIORITY COMMAND   -DEST   PORT (SOURCE HOST)
#define HPSDR_E_BPORT_WB_DAT 1027 // WIDEBAND DATA BASE PORT -SOURCE PORT (SOURCE HARDWARE)
#define HPSDR_E_PORT_DDC_AUD 1028 // DCC AUDIO PROTOCOL      -DEST   PORT (SOURCE HOST)
#define HPSDR_E_BPORT_DUC_IQ 1029 // DUC IQ DATA BASE PORT   -DEST   PORT (SOURCE HOST)
#define HPSDR_E_BPORT_DDC_IQ 1035 // DDC IQ DATA BASE PORT   -SOURCE PORT (SOURCE HARDWARE)

//GENERIC BITMAKS
#define ZERO_MASK      0x00
#define BOOLEAN_MASK   0x08   // ???? CORRECT ????
#define BIT8_MASK      0xFF
#define BIT16_MASK     0xFFFF
#define MASKBITS_1_0   0x03 //0b00000011
#define MASKBITS_2_1_0 0x07 //0b00000111

//BOOLEAN BIT BITMAKS
#define BOOLEAN_B0 0x01 //0b00000001
#define BOOLEAN_B1 0x02 //0b00000010
#define BOOLEAN_B2 0x04 //0b00000100
#define BOOLEAN_B3 0x08 //0b00001000
#define BOOLEAN_B4 0x10 //0b00010000
#define BOOLEAN_B5 0x20 //0b00100000
#define BOOLEAN_B6 0x40 //0b01000000
#define BOOLEAN_B7 0x80 //0b10000000

// BITMASKS
#define MASKBITS_2_1_0 0x07 //0b00000111

//COMMAND REPLY (CR) PORT 1024 MASKS
//#define CR_DISC_FREQ_PHASE 0x01

gint cr_packet_end_pad(tvbuff_t *tvb, proto_tree *tree, gint offset, gint size);
guint8 gc_discovery_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
void cr_check_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset);
void proto_register_hpsdr_u(void);
static void dissect_openhpsdr_e_cr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_cr_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
    void *data);
static void dissect_openhpsdr_e_ddcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_ddcc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_hps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_hps_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_ducc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_ducc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_wbd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_wbd_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_hpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_hpc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_duciq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_duciq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_ddciq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_ddciq_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
static void dissect_openhpsdr_e_mem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean dissect_openhpsdr_e_mem_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data);
void proto_reg_handoff_openhpsdr_e(void);



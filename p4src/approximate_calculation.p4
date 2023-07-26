#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

struct metadata_t {approximate_calculation_metadata_t ac_md;}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_calc;
    }
    state parse_calc {
        pkt.extract(hdr.calc);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
        ) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action get_info_action(bit<8> info) {
        ig_md.ac_md.info = info;
    }

    table get_info_table {
        key = {
            hdr.calc.x[15:15] : exact;
            hdr.calc.y[15:15] : exact;
            ig_md.ac_md.sign[15:15] : exact;
        }
        actions = {
            get_info_action;
        }
        size = 8; 
    }

    action get_log_i_action(int<16> log_i) {
        ig_md.ac_md.log_i = log_i;
    }

    table get_log_i_table {
        key = {
            ig_md.ac_md.frac_x : exact;
        }

        actions = {
            get_log_i_action;
        }

        size = 32768; 
    }

    action get_log_j_action(int<16> log_j) {
        ig_md.ac_md.log_j = log_j;
    }
    
    table get_log_j_table {
        key = {
            ig_md.ac_md.frac_y : exact;
        }

        actions = {
            get_log_j_action;
        }

        size = 32768; 
    }

    action set_flag_0_action(bit<16> sign_z) {
        ig_md.ac_md.flag = 0;
        ig_md.ac_md.sign_z = sign_z;
    }

    action set_flag_1_action(bit<16> sign_z) {
        ig_md.ac_md.flag = 1;
        ig_md.ac_md.sign_z = sign_z;

    }

    action set_flag_2_action(bit<16> sign_z) {
        ig_md.ac_md.flag = 2;
        ig_md.ac_md.sign_z = sign_z;
    }

    table get_flag_table {
        key = {
           ig_md.ac_md.info : exact;
        }
        actions = {
            set_flag_0_action;
            set_flag_1_action;
            set_flag_2_action;
        }

        size = 8; 
    }

    action get_log_m_0_action(int<16> log_m) {
        ig_md.ac_md.log_m = log_m;
    }

    @force_immediate(1)
    table get_log_m_0_table {
        key = {
           ig_md.ac_md.log_k : exact;
        }
        actions = {
            get_log_m_0_action;
        }
        size = 65536; 
    }

    action get_log_m_1_action(int<16> log_m) {
        ig_md.ac_md.log_m = log_m;
    }

    action log_k_zero_1_action() {
        hdr.calc.z = 0;
        exit;          
    }

    table get_log_m_1_table {
        key = {
           ig_md.ac_md.log_k : exact;
        }
        actions = {
            get_log_m_1_action;
            log_k_zero_1_action;
        }

        default_action = log_k_zero_1_action();
        size = 32768; 
    }

    action get_log_m_2_action(int<16> log_m) {
        ig_md.ac_md.log_m = log_m;
    }

    action log_k_zero_2_action() {
        hdr.calc.z = 0;
        exit;          
    }

    table get_log_m_2_table {
        key = {
           ig_md.ac_md.log_k : exact;
        }
        actions = {
            get_log_m_2_action;
            log_k_zero_2_action;
        }

        default_action = log_k_zero_2_action();
        size = 32768; 
    }

    action get_abs_z_action(bit<16> abs_z) {
        hdr.calc.z = abs_z;
    }

    @force_immediate(1)
    table get_abs_z_table {
        key = {
           ig_md.ac_md.n : exact;
        }
        actions = {
            get_abs_z_action;
        }

        size = 65536; 
    }

    apply {
        ig_md.ac_md.frac_x = (bit<16>) hdr.calc.x[14:0];
        ig_md.ac_md.frac_y = (bit<16>) hdr.calc.y[14:0];
        ig_md.ac_md.sign = ig_md.ac_md.frac_x - ig_md.ac_md.frac_y;
        get_info_table.apply();

        ig_tm_md.ucast_egress_port = 130;
        ig_tm_md.bypass_egress = 1w1;

        get_log_i_table.apply();
        get_log_j_table.apply();
        ig_md.ac_md.log_k = ig_md.ac_md.log_j - ig_md.ac_md.log_i;

        switch(get_flag_table.apply().action_run) {
            set_flag_0_action: { get_log_m_0_table.apply(); } //log_m = log(1+2^(j-i))
            set_flag_1_action: { get_log_m_1_table.apply(); } //log_m = log(1-2^(j-i))
            set_flag_2_action: { get_log_m_2_table.apply(); } //log_m = log(-1+2^(j-i)) 
        }
        ig_md.ac_md.n = ig_md.ac_md.log_i + ig_md.ac_md.log_m;
        get_abs_z_table.apply();
        hdr.calc.z = hdr.calc.z | ig_md.ac_md.sign_z;
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
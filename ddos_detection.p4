/*******************************************************************************
 * DDoS Detection
 ******************************************************************************/
 #include<core.p4>
 #include<tna.p4>
 #include"common/headers.p4"
 #include"common/util.p4"

 #define DDOS_SKETCH_SIZE 256
 #define SKETCH_INDEX_WIDTH 8
 #define SKETCH_COUNTER_WIDTH 32 //与WINDOW_COUNTER_WIDTH位宽相同
 #define PKG_COUNTER_WIDTH 16
 #define WINDOW_COUNTER_WIDTH 32
 #define THRESHOLD 600
 #define WINDOWSIZE 10000


 header resubmit{
    bit<16>  statusfinal;
    bit<8>  statusthis;
 }

 @flexible
 header bridge_scnt{
    bit<SKETCH_COUNTER_WIDTH> src_cnt1;	
    bit<SKETCH_COUNTER_WIDTH> src_cnt2;	
 }
 @flexible
 header bridge_dcnt {
    bit<SKETCH_COUNTER_WIDTH> dst_cnt1;	
    bit<SKETCH_COUNTER_WIDTH> dst_cnt2;	
 }
 @flexible
 header bridge_status{
    bit<SKETCH_INDEX_WIDTH> dst_hash2;
    bit<16>  statusfinal;
    bit<16>  statusthis;
    bit<PKG_COUNTER_WIDTH> pkgnum;
    bit<8>   flag;
 }


 struct ddos_metadata_t {
    
    bit<SKETCH_INDEX_WIDTH> src_hash1;
    bit<SKETCH_INDEX_WIDTH> src_hash2;
    bit<SKETCH_INDEX_WIDTH> src_hash3;
    bit<SKETCH_INDEX_WIDTH> src_hash4;

    bit<SKETCH_INDEX_WIDTH> dst_hash1;
    bit<SKETCH_INDEX_WIDTH> dst_hash2;
    bit<SKETCH_INDEX_WIDTH> dst_hash3;
    bit<SKETCH_INDEX_WIDTH> dst_hash4;

    bit<SKETCH_COUNTER_WIDTH> src_cnt1;
    bit<SKETCH_COUNTER_WIDTH> src_cnt2;
    bit<SKETCH_COUNTER_WIDTH> src_cnt3;
    bit<SKETCH_COUNTER_WIDTH> src_cnt4;

    bit<SKETCH_COUNTER_WIDTH> dst_cnt1;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt2;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt3;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt4;

    bit<SKETCH_COUNTER_WIDTH> src_cnt11;
    bit<SKETCH_COUNTER_WIDTH> src_cnt12;
    bit<SKETCH_COUNTER_WIDTH> src_cnt13;
    bit<SKETCH_COUNTER_WIDTH> src_cnt14;

    bit<SKETCH_COUNTER_WIDTH> dst_cnt11;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt12;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt13;
    bit<SKETCH_COUNTER_WIDTH> dst_cnt14;

    bit<SKETCH_COUNTER_WIDTH> diff_cnt1;	
    bit<SKETCH_COUNTER_WIDTH> diff_cnt2;
    bit<SKETCH_COUNTER_WIDTH> diff_change_cnt;	

    bit<32> src_epy;
    bit<32> dst_epy;

    bit<32> src_S;
    bit<32> dst_S;
    bit<32> S_diff_change;

    bit<16> dwin;
    bit<16> swin;
    bit<8>  statuspre;
    bit<8>  statusthis;
    bit<16>  statusfinal;

    bit<16> threshold;
     
    bit<32> dst_ip_flag;

    bit<8> flag;//用于判断当前是哪一个sketch在工作
    bit<WINDOW_COUNTER_WIDTH> wid; //用于记录窗口的id
    bit<PKG_COUNTER_WIDTH> pkgnum; //用于记录数据包的数量

    //bit<8> safeflag;//用于判断当前有没有受到攻击
 }

 struct metadata_t {
    ddos_metadata_t md_ddos;
    resubmit r;
    bridge_scnt sc;
    bridge_dcnt dc;
    bridge_status s;
 }
 struct box {
    bit<SKETCH_COUNTER_WIDTH>      cnt;
    bit<WINDOW_COUNTER_WIDTH>      wid;
 }


// ---------------------------------------------------------------------------
// Ingress Parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        ig_md.dc.setValid();
        ig_md.sc.setValid();
        ig_md.s.setValid();
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.extract(ig_md.r);
        transition parse_ethernet;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
    state parse_icmp {
        pkt.extract(hdr.icmp);
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
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Resubmit() resubmit;
    apply {
        if (ig_dprsr_md.resubmit_type == 3) {
            resubmit.emit(ig_md.r);
        }
        pkt.emit(ig_md.s);
        pkt.emit(ig_md.dc);
        pkt.emit(ig_md.sc);
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Ingress: Hash + Count_min_sketch
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

//register_define{
    //Sketch for ip.src, 4 rows
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash_reg1;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash_reg1) ddos_srchash_reg1_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash_reg2;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash_reg2) ddos_srchash_reg2_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash_reg3;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash_reg3) ddos_srchash_reg3_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash_reg4;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash_reg4) ddos_srchash_reg4_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };

    //Sketch for ip.dst, 4 rows
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash_reg1;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash_reg1) ddos_dsthash_reg1_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
	    }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash_reg2;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash_reg2) ddos_dsthash_reg2_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash_reg3;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash_reg3) ddos_dsthash_reg3_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash_reg4;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash_reg4) ddos_dsthash_reg4_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 0)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 0)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };

    //Sketch2 for ip.src, 4 rows
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash2_reg1;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash2_reg1) ddos_srchash2_reg1_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash2_reg2;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash2_reg2) ddos_srchash2_reg2_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash2_reg3;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash2_reg3) ddos_srchash2_reg3_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_srchash2_reg4;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_srchash2_reg4) ddos_srchash2_reg4_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };

    //Sketch2 for ip.dst, 4 rows
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash2_reg1;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash2_reg1) ddos_dsthash2_reg1_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash2_reg2;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash2_reg2) ddos_dsthash2_reg2_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash2_reg3;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash2_reg3) ddos_dsthash2_reg3_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
    Register<box,bit<SKETCH_INDEX_WIDTH>>(size=DDOS_SKETCH_SIZE,initial_value={0, 0}) ddos_dsthash2_reg4;
    RegisterAction<box, bit<SKETCH_INDEX_WIDTH>, bit<SKETCH_COUNTER_WIDTH>>(ddos_dsthash2_reg4) ddos_dsthash2_reg4_op = {
        void apply(inout box val, out bit<SKETCH_COUNTER_WIDTH> rv) {
            if((ig_md.md_ddos.wid == val.wid) && (ig_md.md_ddos.flag == 1)){
                val.cnt = val.cnt + 1;
            }
	        if((ig_md.md_ddos.wid != val.wid)  && (ig_md.md_ddos.flag == 1)){
                val.cnt = 1;
                val.wid = ig_md.md_ddos.wid;
            }
            rv=val.cnt;
        }
    };
//}
//hash_define{
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.IDENTITY) hash1;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.IDENTITY) hash21;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.RANDOM) hash2;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.RANDOM) hash22;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.CRC8) hash3;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.CRC16) hash4;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.CRC8) hash23;
    Hash<bit<SKETCH_INDEX_WIDTH>>(HashAlgorithm_t.CRC16) hash24;

    action compute_hash1(){
        ig_md.md_ddos.src_hash1 = hash1.get(hdr.ipv4.src_addr);
        ig_md.md_ddos.dst_hash1 = hash21.get(hdr.ipv4.dst_addr);
    }
    action compute_hash2(){
        ig_md.md_ddos.src_hash2 = hash2.get(hdr.ipv4.src_addr);
        ig_md.md_ddos.dst_hash2 = hash22.get(hdr.ipv4.dst_addr);
    }
    action compute_hash3(){
        ig_md.md_ddos.src_hash3 = hash3.get(hdr.ipv4.src_addr);
        ig_md.md_ddos.dst_hash3 = hash23.get(hdr.ipv4.dst_addr);
    }
    action compute_hash4(){
        ig_md.md_ddos.src_hash4 = hash4.get(hdr.ipv4.src_addr);
        ig_md.md_ddos.dst_hash4 = hash24.get(hdr.ipv4.dst_addr);
    }
//}
//counter_define{
    //counter for window id
    Register<bit<WINDOW_COUNTER_WIDTH>,_>(1,0) window_cnt;
    RegisterAction<bit<WINDOW_COUNTER_WIDTH>, _, bit<WINDOW_COUNTER_WIDTH>>(window_cnt) window_cnt_update = {
        void apply(inout bit<WINDOW_COUNTER_WIDTH> val, out bit<WINDOW_COUNTER_WIDTH> rv) {
            val = val+1;
            rv = val;
        }
    };

    //counter for window status
    Register<bit<8>,_>(1,0) window_flag;
    RegisterAction<bit<8>, _, bit<8>>(window_flag) window_flag_update = {
        void apply(inout bit<8> val, out bit<8> rv) {
            if(val == 0) val = 1;
            else val = 0;
            rv=val;
        }
    };

    //counter for pkg number
    Register<bit<PKG_COUNTER_WIDTH>,_>(1,0) pkg_cnt;
    RegisterAction<bit<PKG_COUNTER_WIDTH>, _, bit<PKG_COUNTER_WIDTH>>(pkg_cnt) pkg_cnt_op = {
        void apply(inout bit<PKG_COUNTER_WIDTH> val, out bit<PKG_COUNTER_WIDTH> rv) {
            if(val == WINDOWSIZE){//important
                val = 1;
            }else{
                val = val + 1;
            }
		    rv = val;
        }
    };
//}*/

//获取最小值{
    
    action get_src_min1(){
        if(ig_md.md_ddos.src_cnt2>ig_md.md_ddos.src_cnt1) ig_md.md_ddos.src_cnt2 = ig_md.md_ddos.src_cnt1;
	    if(ig_md.md_ddos.dst_cnt2>ig_md.md_ddos.dst_cnt1) ig_md.md_ddos.dst_cnt2 = ig_md.md_ddos.dst_cnt1;
        if(ig_md.md_ddos.src_cnt4>ig_md.md_ddos.src_cnt3) ig_md.md_ddos.src_cnt4 = ig_md.md_ddos.src_cnt3;
	    if(ig_md.md_ddos.dst_cnt4>ig_md.md_ddos.dst_cnt3) ig_md.md_ddos.dst_cnt4 = ig_md.md_ddos.dst_cnt3;
    }
    action get_src_min2(){
        if(ig_md.md_ddos.src_cnt3>ig_md.md_ddos.src_cnt2) ig_md.md_ddos.src_cnt3 = ig_md.md_ddos.src_cnt2;
	    if(ig_md.md_ddos.dst_cnt3>ig_md.md_ddos.dst_cnt2) ig_md.md_ddos.dst_cnt3 = ig_md.md_ddos.dst_cnt2;
    }

    action get_src_min3(){
        if(ig_md.md_ddos.src_cnt12>ig_md.md_ddos.src_cnt11) ig_md.md_ddos.src_cnt12 = ig_md.md_ddos.src_cnt11;
	    if(ig_md.md_ddos.dst_cnt12>ig_md.md_ddos.dst_cnt11) ig_md.md_ddos.dst_cnt12 = ig_md.md_ddos.dst_cnt11;
        if(ig_md.md_ddos.src_cnt14>ig_md.md_ddos.src_cnt13) ig_md.md_ddos.src_cnt14 = ig_md.md_ddos.src_cnt13;
	    if(ig_md.md_ddos.dst_cnt14>ig_md.md_ddos.dst_cnt13) ig_md.md_ddos.dst_cnt14 = ig_md.md_ddos.dst_cnt13;
    }
    action get_src_min4(){
        if(ig_md.md_ddos.src_cnt13>ig_md.md_ddos.src_cnt12) ig_md.md_ddos.src_cnt13 = ig_md.md_ddos.src_cnt12;
	    if(ig_md.md_ddos.dst_cnt13>ig_md.md_ddos.dst_cnt12) ig_md.md_ddos.dst_cnt13 = ig_md.md_ddos.dst_cnt12;
    }

//}

//计算香农熵{    
        action src_entropy_compute(bit<32> entropy_term){
            ig_md.md_ddos.src_epy = entropy_term;
        }
        table src_entropy{
            key = {
                ig_md.md_ddos.src_cnt3:exact;
            }
            actions = {
                src_entropy_compute;
            }
            default_action = src_entropy_compute(0);
            size = WINDOWSIZE;
        }
        table src2_entropy{
            key = {
                ig_md.md_ddos.src_cnt13:exact;
            }
            actions = {
                src_entropy_compute;
            }
            default_action = src_entropy_compute(0);
            size = WINDOWSIZE;
        }
        action dst_entropy_compute(bit<32> entropy_term){
            ig_md.md_ddos.dst_epy = entropy_term;
        }
        table dst_entropy{
            key = {
                ig_md.md_ddos.dst_cnt3:exact;
            }
            actions = {
                dst_entropy_compute;
            }
            default_action = dst_entropy_compute(0);
            size = WINDOWSIZE;
        }
        table dst2_entropy{
            key = {
                ig_md.md_ddos.dst_cnt13:exact;
            }
            actions = {
                dst_entropy_compute;
            }
            default_action = dst_entropy_compute(0);
            size = WINDOWSIZE;
        }
        
        Register<bit<32>,_>(1,0) src_S;
        RegisterAction<bit<32>, _, bit<32>>(src_S) src_S_update = {
            void apply(inout bit<32> val, out bit<32> rv) {
		        if(ig_md.md_ddos.pkgnum == 1){
		            val = 0;
		        }else{
                    val = val + ig_md.md_ddos.src_epy;
		        }
                rv = val;
            }
        };
        Register<bit<32>,_>(1,0) dst_S;
        RegisterAction<bit<32>, _, bit<32>>(dst_S) dst_S_update = {
            void apply(inout bit<32> val, out bit<32> rv) {
		        if(ig_md.md_ddos.pkgnum == 1){
		            val = 0;
		        }else{
                    val = val + ig_md.md_ddos.dst_epy;
		        }
                rv = val;
            }
        };
//}

    action diff(){
        ig_md.md_ddos.S_diff_change = ig_md.md_ddos.dst_S |-| ig_md.md_ddos.src_S;
    }

//}
    Register<bit<16>,_>(1,0) safe_window_cnt;
    RegisterAction<bit<16>, _, bit<16>>(safe_window_cnt) safe_window_cnt_update = {
         void apply(inout bit<16> val, out bit<16> rv) {
            if(ig_md.md_ddos.statusthis == 0) val = val + 1;
            else val=0;
                rv = val;
        }
    };
    Register<bit<16>,_>(1,0) danger_window_cnt;
    RegisterAction<bit<16>, _, bit<16>>(danger_window_cnt) danger_window_cnt_update = {
         void apply(inout bit<16> val, out bit<16> rv) {
            if(ig_md.md_ddos.statusthis == 1) val = val + 1;
            else val=0;
            rv = val;
        }
    };
    Register<bit<16>,_>(1,0) status_final;
    RegisterAction<bit<16>, _, bit<16>>(status_final) status_final_update = {
         void apply(inout bit<16> val, out bit<16> rv) {
	        if(ig_md.md_ddos.dwin >= 3) val = 1;
            if(ig_md.md_ddos.swin >= 3) val = 0;
            rv = val;
        }
    };

    apply{
        if(ig_intr_md.ingress_port == 142){
            ig_tm_md.ucast_egress_port = 141;
            //ig_tm_md.bypass_egress = 1;
        }
        if(ig_intr_md.ingress_port == 141){
            ig_tm_md.ucast_egress_port = 142;
            //ig_tm_md.bypass_egress = 1;
        }

        if(ig_intr_md.resubmit_flag == 1 && ig_md.r.statusthis == 0){
            ig_md.md_ddos.flag = window_flag_update.execute(0);
            ig_md.md_ddos.wid = window_cnt_update.execute(0);
            hdr.ipv4.src_addr=0x00000005;
            hdr.ipv4.dst_addr[31:16]=0x0101;//testing resubmit
            hdr.ipv4.dst_addr[15:0]=ig_md.r.statusfinal;//testing resubmit
            //ig_tm_md.bypass_egress = 1;
        }
        else if(ig_intr_md.resubmit_flag == 1 && ig_md.r.statusthis == 1){
            ig_md.md_ddos.wid = window_cnt_update.execute(0);
            hdr.ipv4.src_addr=0x00000005;
            hdr.ipv4.dst_addr[31:16]=0x0101;//testing resubmit
            hdr.ipv4.dst_addr[15:0]=ig_md.r.statusfinal;//testing resubmit
            //ig_tm_md.bypass_egress = 1;
        }else{
            ig_md.md_ddos.flag = window_flag.read(0);
            ig_md.md_ddos.wid = window_cnt.read(0);
            ig_md.md_ddos.pkgnum = pkg_cnt_op.execute(0);
        }

        //ig_md.md_ddos.wid = window_cnt.read(0); //cant be accesssed twice
 //error
        /*if(ig_md.md_ddos.pkgnum == WINDOWSIZE){
            ig_md.md_ddos.flag = window_flag_update(0);
            ig_md.md_ddos.wid = window_cnt_update.execute(0);
        }*/

        compute_hash1();
        compute_hash2();
        compute_hash3();
        compute_hash4();
        
        //if(ig_md.md_ddos.flag==0){
        //ig_md.md_ddos.src_cnt1 = ddos_srchash_reg1_op.execute(ig_md.md_ddos.src_hash1);
        ig_md.md_ddos.src_cnt2 = ddos_srchash_reg2_op.execute(ig_md.md_ddos.src_hash2);
        ig_md.md_ddos.src_cnt3 = ddos_srchash_reg3_op.execute(ig_md.md_ddos.src_hash3);
        //ig_md.md_ddos.src_cnt4 = ddos_srchash_reg4_op.execute(ig_md.md_ddos.src_hash4);
        //ig_md.md_ddos.dst_cnt1 = ddos_dsthash_reg1_op.execute(ig_md.md_ddos.dst_hash1);
        ig_md.md_ddos.dst_cnt2 = ddos_dsthash_reg2_op.execute(ig_md.md_ddos.dst_hash2);
        ig_md.md_ddos.dst_cnt3 = ddos_dsthash_reg3_op.execute(ig_md.md_ddos.dst_hash3);
        //ig_md.md_ddos.dst_cnt4 = ddos_dsthash_reg4_op.execute(ig_md.md_ddos.dst_hash4);
        //ig_md.md_ddos.src_cnt11 = ddos_srchash2_reg1_op.execute(ig_md.md_ddos.src_hash1);
        ig_md.md_ddos.src_cnt12 = ddos_srchash2_reg2_op.execute(ig_md.md_ddos.src_hash2);
        ig_md.md_ddos.src_cnt13 = ddos_srchash2_reg3_op.execute(ig_md.md_ddos.src_hash3);
        //ig_md.md_ddos.src_cnt14 = ddos_srchash2_reg4_op.execute(ig_md.md_ddos.src_hash4);
        //ig_md.md_ddos.dst_cnt11 = ddos_dsthash2_reg1_op.execute(ig_md.md_ddos.dst_hash1);
        ig_md.md_ddos.dst_cnt12 = ddos_dsthash2_reg2_op.execute(ig_md.md_ddos.dst_hash2);
        ig_md.md_ddos.dst_cnt13 = ddos_dsthash2_reg3_op.execute(ig_md.md_ddos.dst_hash3);
        //ig_md.md_ddos.dst_cnt14 = ddos_dsthash2_reg4_op.execute(ig_md.md_ddos.dst_hash4);
        //}
        /*else{
        //ig_md.md_ddos.src_cnt11 = ddos_srchash_reg1_op.execute(ig_md.md_ddos.src_hash1);
        ig_md.md_ddos.src_cnt12 = ddos_srchash_reg2_op.execute(ig_md.md_ddos.src_hash2);
        ig_md.md_ddos.src_cnt13 = ddos_srchash_reg3_op.execute(ig_md.md_ddos.src_hash3);
        //ig_md.md_ddos.src_cnt14 = ddos_srchash_reg4_op.execute(ig_md.md_ddos.src_hash4);
        //ig_md.md_ddos.dst_cnt11 = ddos_dsthash_reg1_op.execute(ig_md.md_ddos.dst_hash1);
        ig_md.md_ddos.dst_cnt12 = ddos_dsthash_reg2_op.execute(ig_md.md_ddos.dst_hash2);
        ig_md.md_ddos.dst_cnt13 = ddos_dsthash_reg3_op.execute(ig_md.md_ddos.dst_hash3);
        //ig_md.md_ddos.dst_cnt14 = ddos_dsthash_reg4_op.execute(ig_md.md_ddos.dst_hash4);
        //ig_md.md_ddos.src_cnt1 = ddos_srchash2_reg1_op.execute(ig_md.md_ddos.src_hash1);
        ig_md.md_ddos.src_cnt2 = ddos_srchash2_reg2_op.execute(ig_md.md_ddos.src_hash2);
        ig_md.md_ddos.src_cnt3 = ddos_srchash2_reg3_op.execute(ig_md.md_ddos.src_hash3);
        //ig_md.md_ddos.src_cnt4 = ddos_srchash2_reg4_op.execute(ig_md.md_ddos.src_hash4);
        //ig_md.md_ddos.dst_cnt1 = ddos_dsthash2_reg1_op.execute(ig_md.md_ddos.dst_hash1);
        ig_md.md_ddos.dst_cnt2 = ddos_dsthash2_reg2_op.execute(ig_md.md_ddos.dst_hash2);
        ig_md.md_ddos.dst_cnt3 = ddos_dsthash2_reg3_op.execute(ig_md.md_ddos.dst_hash3);
        //ig_md.md_ddos.dst_cnt4 = ddos_dsthash2_reg4_op.execute(ig_md.md_ddos.dst_hash4);            
        }*/

		//get_src_min1();
		get_src_min2();
		//get_src_min3();
		get_src_min4();

        //ig_md.md_ddos.src_cnt3,ig_md.md_ddos.dst_cnt3就是最终的计数结果
        //下一步进入计算熵值阶段
	if(ig_md.md_ddos.flag==0){
		src_entropy.apply();
		dst_entropy.apply();
	}
	else{
		src2_entropy.apply();
		dst2_entropy.apply();
	}	

        //开始计算香农熵
        ig_md.md_ddos.src_S = src_S_update.execute(0);
        ig_md.md_ddos.dst_S = dst_S_update.execute(0);
        //至此计算得到了源目地址的熵范数
        /*for testing
        if(ig_intr_md.resubmit_flag == 0){
            hdr.ipv4.src_addr=src_S_update.execute(0);
            hdr.ipv4.dst_addr=dst_S_update.execute(0);
        }*/

        diff();
        if(ig_md.md_ddos.S_diff_change >= 0x00000200) 
            ig_md.md_ddos.statusthis=1;//use >=, do not use >
	    else 
            ig_md.md_ddos.statusthis=0;

        if(ig_md.md_ddos.pkgnum == WINDOWSIZE){
            ig_md.md_ddos.dwin = danger_window_cnt_update.execute(0);
            ig_md.md_ddos.swin = safe_window_cnt_update.execute(0);
        }else{
            ig_md.md_ddos.dwin = danger_window_cnt.read(0);
            ig_md.md_ddos.swin = safe_window_cnt.read(0);            
        }

	    ig_md.md_ddos.statusfinal=status_final_update.execute(0);
        ig_md.r.statusthis=ig_md.md_ddos.statusthis;
        ig_md.r.statusfinal=status_final_update.execute(0);
        ig_md.s.statusfinal=status_final_update.execute(0);

        ig_md.s.flag = ig_md.md_ddos.flag;
        ig_md.s.dst_hash2 = ig_md.md_ddos.dst_hash2;
        ig_md.s.pkgnum = ig_md.md_ddos.pkgnum;
        ig_md.sc.src_cnt1 = ig_md.md_ddos.src_cnt3;
        ig_md.sc.src_cnt2 = ig_md.md_ddos.src_cnt13;
        ig_md.dc.dst_cnt1 = ig_md.md_ddos.dst_cnt3;
        ig_md.dc.dst_cnt2 = ig_md.md_ddos.dst_cnt13;
        //hdr.ipv4.src_addr[15:0]=ig_md.s.statusfinal;

        if(ig_md.md_ddos.pkgnum == WINDOWSIZE){
            ig_dprsr_md.resubmit_type = 3;
        }
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        pkt.extract(eg_md.s);
        pkt.extract(eg_md.dc);
        pkt.extract(eg_md.sc);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
}
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply{
        pkt.emit(hdr);
    }   
}

control SwitchEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in    egress_intrinsic_metadata_t                 eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Register<bit<32>,_>(256, 0) dst_key;
    RegisterAction<bit<32>, _ , bit<32>>(dst_key) dst_key_op = {
        void apply(inout bit<32> val, out bit<32> rv){
            if(eg_md.md_ddos.diff_change_cnt >= 0x00000120)
                val = hdr.ipv4.dst_addr;
            if(eg_md.md_ddos.diff_change_cnt <= 0x00000060)
                val=0;
            rv  = val;
        }
    };
    RegisterAction<bit<32>, _ , bit<32>>(dst_key) dst_key_clean = {
        void apply(inout bit<32> val, out bit<32> rv){
            val = 0;
        }
    };


    Register<bit<32>,_>(256, 0) dst_flag;
    RegisterAction<bit<32>, _, bit<32>>(dst_flag) dst_flag_op = {
        void apply(inout bit<32> val, out bit<32> rv) {
            if(eg_md.md_ddos.diff_change_cnt >= 0x00000100)
                val = 1;
            if(eg_md.md_ddos.diff_change_cnt <= 0x00000060)
                val=0;
            rv  = val;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(dst_flag) dst_flag_read = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv  = val;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(dst_flag) dst_flag_clean = {
        void apply(inout bit<32> val, out bit<32> rv) {
            val = 0;
            rv  = 0;
        }
    };
    Register<bit<16>,_>(256, 0) counter;
    RegisterAction<bit<16>, _, bit<16>>(counter) counter_op = {
        void apply(inout bit<16> val, out bit<16> rv) {
            if(eg_md.s.pkgnum >= val )
                val = eg_md.s.pkgnum;
            if(eg_md.s.statusfinal == 0)
                val=0;
            rv  = val;
        }
    };


    action diff1(){
        eg_md.md_ddos.diff_change_cnt = eg_md.md_ddos.diff_cnt1 |-| eg_md.md_ddos.diff_cnt2;
    }
    action diff2(){
        eg_md.md_ddos.diff_change_cnt = eg_md.md_ddos.diff_cnt2 |-| eg_md.md_ddos.diff_cnt1;
    }
    apply { 
        eg_md.md_ddos.pkgnum = counter_op.execute(eg_md.s.dst_hash2);
        eg_md.md_ddos.diff_cnt1= eg_md.dc.dst_cnt1 |-| eg_md.sc.src_cnt1;
        eg_md.md_ddos.diff_cnt2= eg_md.dc.dst_cnt2 |-| eg_md.sc.src_cnt2;
        if((eg_md.s.statusfinal == 1) && (eg_md.s.flag==0)){ //start filter
            diff1();
        }	
        else if((eg_md.s.statusfinal == 1) && (eg_md.s.flag==1)){ //start filter
//            ig_md.md_ddos.diff_src_cnt = ig_md.md_ddos.src_cnt13 |-| ig_md.md_ddos.src_cnt3;
            diff2();
        }
        if(eg_md.s.statusfinal == 1){
            if(eg_md.s.pkgnum == eg_md.md_ddos.pkgnum){
                eg_md.md_ddos.dst_ip_flag = dst_flag_op.execute(eg_md.s.dst_hash2);
                dst_key_op.execute(eg_md.s.dst_hash2);
            }else{
                eg_md.md_ddos.dst_ip_flag = dst_flag_read.execute(eg_md.s.dst_hash2);
            }
        }
        else{
            eg_md.md_ddos.dst_ip_flag = dst_flag_clean.execute(eg_md.s.dst_hash2);
            eg_md.md_ddos.dst_ip_flag = dst_key_clean.execute(eg_md.s.dst_hash2);
        }
        /*if(eg_md.md_ddos.diff_dst_cnt>= 0x0190){
            hdr.ipv4.src_addr=0x01010002;
            //eg_dprsr_md.drop_ctl=0b111; //drop
        }*/
        if(hdr.ipv4.src_addr==0x00000005){
            eg_md.md_ddos.dst_ip_flag=0;
        }

        if(eg_md.md_ddos.dst_ip_flag== 1){
            //eg_dprsr_md.drop_ctl=0b111; //drop
            hdr.ipv4.src_addr=0x01010002;
        }
        //hdr.ipv4.dst_addr[15:0] = eg_md.s.statusfinal;
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
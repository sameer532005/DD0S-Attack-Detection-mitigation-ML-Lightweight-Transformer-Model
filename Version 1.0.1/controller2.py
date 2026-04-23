#!/usr/bin/env python3

import csv
import ipaddress
import os
import time
from pathlib import Path

import joblib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet
from ryu.ofproto import ofproto_v1_3

DATASET_PATH = Path("flow_stats.csv")
MODEL_PATH = Path("ddos_random_forest.joblib")

MONITOR_INTERVAL = 1
ATTACK_LABEL = 1
VICTIM_IP = "10.0.0.6"


class DDoSMLController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSMLController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_ips = set()
        self.model = self._load_model()

        self.attack_sources = set()
        self.last_reset = time.time()

        self._ensure_dataset()
        self.monitor_thread = hub.spawn(self._monitor)

    def _load_model(self):
        if not MODEL_PATH.exists():
            print("⚠ No model found, collecting CSV only")
            return None
        print("✅ Model loaded")
        return joblib.load(MODEL_PATH)

    def _ensure_dataset(self):
        if not DATASET_PATH.exists():
            with DATASET_PATH.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp","switch_id","src_ip","dst_ip",
                    "src_ip_int","dst_ip_int","protocol",
                    "packet_count","byte_count","duration_sec","duration_nsec",
                    "packet_rate","byte_rate","label"
                ])

    def _ip_to_int(self, ip):
        try:
            return int(ipaddress.ip_address(ip))
        except:
            return 0

    def _safe_rate(self, count, sec, nsec):
        duration = sec + nsec / 1e9
        return count / duration if duration > 0 else 0

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[ev.datapath.id] = ev.datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(ev.datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(dp, 0, match, actions)

    def add_flow(self, dp, priority, match, actions):
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=0
        )
        dp.send_msg(mod)

    def add_drop_flow(self, dp, ip):
        if ip in self.blocked_ips:
            return

        parser = dp.ofproto_parser

        # block source → victim
        match1 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip
        )

        mod1 = parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=match1,
            instructions=[]
        )
        dp.send_msg(mod1)

        # block reverse just in case
        match2 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=ip
        )

        mod2 = parser.OFPFlowMod(
            datapath=dp,
            priority=100,
            match=match2,
            instructions=[]
        )
        dp.send_msg(mod2)

        self.blocked_ips.add(ip)
        print(f"🚫 BLOCKED IP: {ip}")
        print(f"🛑 ATTACK STOPPED FROM {ip}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src] = in_port

        out_port = self.mac_to_port[dp.id].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        ))

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
            else:
                match = parser.OFPMatch(
                    eth_src=src,
                    eth_dst=dst
                )

            self.add_flow(dp, 10, match, actions)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                parser = dp.ofproto_parser
                ofproto = dp.ofproto

                dp.send_msg(parser.OFPFlowStatsRequest(
                    datapath=dp,
                    table_id=ofproto.OFPTT_ALL
                ))

            hub.sleep(MONITOR_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        for stat in ev.msg.body:

            if stat.priority == 0:
                continue

            src_ip = stat.match.get("ipv4_src")
            dst_ip = stat.match.get("ipv4_dst")

            if not src_ip or not dst_ip:
                continue

            # 🔥 ONLY TRAFFIC TO VICTIM
            if dst_ip != VICTIM_IP:
                continue

            # 🔥 IGNORE REVERSE TRAFFIC
            if src_ip == VICTIM_IP:
                continue

            pkt_rate = self._safe_rate(stat.packet_count, stat.duration_sec, stat.duration_nsec)

            row = [
                int(time.time()),
                ev.msg.datapath.id,
                src_ip,
                dst_ip,
                self._ip_to_int(src_ip),
                self._ip_to_int(dst_ip),
                stat.match.get("ip_proto", 0),
                stat.packet_count,
                stat.byte_count,
                stat.duration_sec,
                stat.duration_nsec,
                pkt_rate,
                0,
                int(os.environ.get("TRAFFIC_LABEL", "0"))
            ]

            if time.time() - self.last_reset > 5:
                self.attack_sources.clear()
                self.last_reset = time.time()

            if self.model:
                pred = self.model.predict([row[4:13]])[0]

                print(f"Prediction: {pred} | {src_ip} → {dst_ip} rate={pkt_rate}")

                if pred == ATTACK_LABEL and pkt_rate > 0.01:
                    self.attack_sources.add(src_ip)

                    if len(self.attack_sources) >= 3:
                          print("🚨 DDoS ATTACK DETECTED - NO MITIGATION (ALLOWING OVERLOAD)")

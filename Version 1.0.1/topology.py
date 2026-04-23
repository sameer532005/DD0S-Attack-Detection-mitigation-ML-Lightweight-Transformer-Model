#!/usr/bin/env python3

import time
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo


class DDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")

        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        h4 = self.addHost("h4", ip="10.0.0.4/24")
        h5 = self.addHost("h5", ip="10.0.0.5/24")
        h6 = self.addHost("h6", ip="10.0.0.6/24")

        for h in [h1, h2, h3, h4, h5, h6]:
            self.addLink(h, s1, cls=TCLink, bw=20)


def run():
    topo = DDoSTopo()
    controller = RemoteController("c0", ip="127.0.0.1", port=6653)

    net = Mininet(
        topo=topo,
        controller=controller,
        switch=OVSKernelSwitch,
        link=TCLink
    )

    net.start()
    time.sleep(2)

    info("*** Testing connectivity\n")
    net.pingAll()

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()

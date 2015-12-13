﻿using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an IPv4 over Ethernet with payload packet.
    /// </summary>
    class IPV4SendPacket : BaseSendPacket
    {
        public Packet IPV4packet;
        public IPV4SendPacket(string MACsrc, string MACdst)
        {
            GetBase(MACsrc, MACdst);

            //CODE HIER
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }
        public void GetBuilder()
        {
            listLayers.Add(ethernetLayer);
            AddLayers(listLayers);
            IPV4packet = builder.Build(DateTime.Now);
        }
    }
}
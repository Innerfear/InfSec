﻿using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an TCP over IPv4 over Ethernet with payload packet.
    /// </summary>
    class TCPSendPacket : BaseSendPacket
    {
        public TCPSendPacket(string MACsrc, string MACdst)
        {
            GetAdresses(MACsrc, MACdst);

            //CODE HIER
        }
        public override void GetAdresses(string MACsrc, string MACdst)
        {
            base.GetAdresses(MACsrc, MACdst);
            ethernetLayer.EtherType = EthernetType.None;
        }
        public override void AddLayers()
        {
            layers.Add();
        }
    }
}

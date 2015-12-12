using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an ICMP over IPv4 over Ethernet packet.
    /// </summary>
    class ICMPSendPacket : BaseSendPacket
    {
        public Packet ICMPpacket;
        public ICMPSendPacket(string MACsrc, string MACdst)
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
            ICMPpacket = builder.Build(DateTime.Now);
        }
    }
}

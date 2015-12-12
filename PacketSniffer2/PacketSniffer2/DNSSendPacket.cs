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
    /// This class builds a DNS over UDP over IPv4 over Ethernet packet.
    /// </summary>
    class DNSSendPacket : BaseSendPacket
    {
        public Packet DNSpacket;
        public DNSSendPacket(string MACsrc, string MACdst)
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
            DNSpacket = builder.Build(DateTime.Now);
        }
    }
}

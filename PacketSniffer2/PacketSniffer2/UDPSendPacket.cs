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
    /// This class builds an UDP over IPv4 over Ethernet with payload packet.
    /// </summary>
    class UDPSendPacket : BaseSendPacket
    {
        public Packet UPDpacket;
        public UDPSendPacket(string MACsrc, string MACdst)
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
            UPDpacket = builder.Build(DateTime.Now);
        }
    }
}

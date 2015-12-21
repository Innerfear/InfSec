using PcapDotNet.Packets;
using System;
using System.Text;

namespace PacketSniffer2
{
    // This class builds an IPv4 over Ethernet with payload packet.
    class IPV4SendPacket : BaseSendPacket
    {
        private Packet IPV4packet;
        private PayloadLayer payloadLayer;
        public IPV4SendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, 
            string IpId, string TTL, string data)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

            payloadLayer = new PayloadLayer
            {
                Data = new Datagram(Encoding.ASCII.GetBytes(data))
            };
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, payloadLayer);
            return IPV4packet = builder.Build(DateTime.Now);
        }
    }
}

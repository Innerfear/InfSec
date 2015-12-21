using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using System;

namespace PacketSniffer2
{
    // This class builds an ICMP over IPv4 over Ethernet packet.
    class ICMPSendPacket : BaseSendPacket
    {
        private Packet ICMPpacket;
        private IcmpEchoLayer icmpLayer;
        public ICMPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL, string Identifier, string SQN)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

            icmpLayer = new IcmpEchoLayer
            {
                Checksum = null, // Will be filled automatically.
                Identifier = StringToUShort(Identifier),
                SequenceNumber = StringToUShort(SQN),
            };
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
            return ICMPpacket = builder.Build(DateTime.Now);
        }
    }
}

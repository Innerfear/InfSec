using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using System;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an ICMP over IPv4 over Ethernet packet.
    /// </summary>
    class ICMPSendPacket : BaseSendPacket
    {
        private Packet ICMPpacket;
        private IpV4Layer ipV4Layer;
        private IcmpEchoLayer icmpLayer;
        public ICMPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string Identifier, string SQN)
        {
            GetBase(MACsrc, MACdst);

           ipV4Layer =
           new IpV4Layer
           {
               Source = new IpV4Address(IPsrc),
               CurrentDestination = new IpV4Address(IPdst),
               Fragmentation = IpV4Fragmentation.None,
               HeaderChecksum = null, // Will be filled automatically.
               Identification = StringToUShort(IpId),
               Options = IpV4Options.None,
               Protocol = null, // Will be filled automatically.
               Ttl = StringToByte(TTL),
               TypeOfService = 0,
           };

            icmpLayer =
            new IcmpEchoLayer
            {
                Checksum = null, // Will be filled automatically.
                Identifier = StringToUShort(Identifier),
                SequenceNumber = StringToUShort(SQN),
            };
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);
            return ICMPpacket = builder.Build(DateTime.Now);
        }
    }
}

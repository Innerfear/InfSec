using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using System;
using System.Text;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an IPv4 over Ethernet with payload packet.
    /// </summary>
    class IPV4SendPacket : BaseSendPacket
    {
        public Packet IPV4packet;
        private IpV4Layer ipV4Layer;
        private PayloadLayer payloadLayer;
        public IPV4SendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string data)
        {
            GetBase(MACsrc, MACdst);

            ipV4Layer = new IpV4Layer
            {
                Source = new IpV4Address(IPsrc),
                CurrentDestination = new IpV4Address(IPdst),
                Fragmentation = IpV4Fragmentation.None,
                HeaderChecksum = null, // will be filled automatically.
                Identification = StringToUShort(IpId),
                Options = IpV4Options.None,
                Protocol = IpV4Protocol.Udp,
                Ttl = StringToByte(TTL),
                TypeOfService = 0
            };

            payloadLayer = new PayloadLayer
            {
                Data = new Datagram(Encoding.ASCII.GetBytes(data))
            };
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, payloadLayer);
            return IPV4packet = builder.Build(DateTime.Now);
        }
    }
}

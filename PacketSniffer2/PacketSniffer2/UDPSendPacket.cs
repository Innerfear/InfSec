using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Text;

namespace PacketSniffer2
{
    // This class builds an UDP over IPv4 over Ethernet with payload packet.
    class UDPSendPacket : BaseSendPacket
    {
        private Packet UPDpacket;
        private IpV4Layer ipV4Layer;
        private UdpLayer udpLayer;
        private PayloadLayer payloadLayer;
        public UDPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL, string PORTsrc, string data)
        {
            GetBase(MACsrc, MACdst);

            ipV4Layer = new IpV4Layer
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

           udpLayer = new UdpLayer
           {
               SourcePort = StringToUShort(PORTsrc),
               DestinationPort = 25,
               Checksum = null, // Will be filled automatically.
               CalculateChecksumValue = true,
           };

             payloadLayer = new PayloadLayer
             {
                 Data = new Datagram(Encoding.ASCII.GetBytes(data)),
             };
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);
            return UPDpacket = builder.Build(DateTime.Now);
        }
    }
}

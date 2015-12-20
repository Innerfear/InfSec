using PcapDotNet.Packets;
using PcapDotNet.Packets.Transport;
using System;
using System.Text;

namespace PacketSniffer2
{
    // This class builds an UDP over IPv4 over Ethernet with payload packet.
    class UDPSendPacket : BaseSendPacket
    {
        private Packet UPDpacket;
        private UdpLayer udpLayer;
        private PayloadLayer payloadLayer;
        public UDPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL, string PORTsrc, string data)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

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
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);
            return UPDpacket = builder.Build(DateTime.Now);
        }
    }
}

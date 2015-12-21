using PcapDotNet.Packets;
using PcapDotNet.Packets.Transport;
using System;
using System.Text;

namespace PacketSniffer2
{
    // This class builds an TCP over IPv4 over Ethernet with payload packet.
    class TCPSendPacket : BaseSendPacket
    {
        private Packet TCPpacket;
        private TcpLayer tcpLayer;
        private PayloadLayer payloadLayer;
        public TCPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, 
            string IpId, string TTL, string PORTsrc, string SQN, string ACK, string WIN, string data)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

            tcpLayer = new TcpLayer
            {
                SourcePort = StringToUShort(PORTsrc),
                DestinationPort = 25,
                Checksum = null, // Will be filled automatically.
                SequenceNumber = StringToUShort(SQN),
                AcknowledgmentNumber = StringToUShort(ACK),
                ControlBits = TcpControlBits.Acknowledgment,
                Window = StringToUShort(WIN),
                UrgentPointer = 0,
                Options = TcpOptions.None,
            };

            payloadLayer = new PayloadLayer
            {
                Data = new Datagram(Encoding.ASCII.GetBytes(data)),
            };
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, payloadLayer);
            return TCPpacket = builder.Build(DateTime.Now);
        }
    }
}

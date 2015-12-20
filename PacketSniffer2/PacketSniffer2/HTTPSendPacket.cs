using PcapDotNet.Packets;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Transport;
using System;
using System.Text;

namespace PacketSniffer2
{
    // This class builds an HTTP over TCP over IPv4 over Ethernet packet.
    class HTTPSendPacket : BaseSendPacket
    {
        private Packet HTTPpacket;
        private TcpLayer tcpLayer;
        private HttpRequestLayer httpLayer;
        public HTTPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL,
            string PORTsrc, string SQN, string ACK, string WIN, string Data, string Domain)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

            tcpLayer = new TcpLayer
            {
                SourcePort = StringToUShort(PORTsrc),
                DestinationPort = 80,
                Checksum = null, // Will be filled automatically.
                SequenceNumber = StringToUShort(SQN),
                AcknowledgmentNumber = StringToUShort(ACK),
                ControlBits = TcpControlBits.Acknowledgment,
                Window = StringToUShort(WIN),
                UrgentPointer = 0,
                Options = TcpOptions.None,
            };

            httpLayer = new HttpRequestLayer
            {
                Version = HttpVersion.Version11,
                Header = new HttpHeader(new HttpContentLengthField(11)),
                Body = new Datagram(Encoding.ASCII.GetBytes(Data)),
                Method = new HttpRequestMethod(HttpRequestKnownMethod.Get),
                Uri = @"http://" + Domain + "/",
            };
        }
        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, httpLayer);
            return HTTPpacket = builder.Build(DateTime.Now);
        }
    }
}

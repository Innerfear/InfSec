using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an TCP over IPv4 over Ethernet with payload packet.
    /// </summary>
    class TCPSendPacket : BaseSendPacket
    {
        public Packet TCPpacket;
        protected IpV4Layer ipv4Layer;
        protected TcpLayer tcpLayer;
        protected PayloadLayer payloadLayer;
        public TCPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string PORTsrc, string PORTdst, string SQN, string ACK, string WIN, string data)
        {
            GetBase(MACsrc, MACdst);

            ipv4Layer =
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

            tcpLayer =
            new TcpLayer
            {
                SourcePort = StringToUShort(PORTsrc),
                DestinationPort = StringToUShort(PORTdst),
                Checksum = null, // Will be filled automatically.
                SequenceNumber = StringToUShort(SQN),
                AcknowledgmentNumber = StringToUShort(ACK),
                ControlBits = TcpControlBits.Acknowledgment,
                Window = StringToUShort(WIN),
                UrgentPointer = 0,
                Options = TcpOptions.None,
            };

            payloadLayer =
            new PayloadLayer
            {
                Data = new Datagram(Encoding.ASCII.GetBytes(data)),
            };
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }
        public void GetBuilder()
        {
            listLayers.Add(ethernetLayer);
            listLayers.Add(ipv4Layer);
            listLayers.Add(tcpLayer);
            listLayers.Add(payloadLayer);
            AddLayers(listLayers);
            TCPpacket = builder.Build(DateTime.Now);
        }
    }
}

﻿using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
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
    /// This class builds an HTTP over TCP over IPv4 over Ethernet packet.
    /// </summary>
    class HTTPSendPacket : BaseSendPacket
    {
        public Packet HTTPpacket;
        protected IpV4Layer ipv4Layer;
        protected TcpLayer tcpLayer;
        protected HttpRequestLayer httpLayer;
        public HTTPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string PORTsrc, string PORTdst, string SQN, string ACK, string WIN, string data, string Domain)
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

            httpLayer =
            new HttpRequestLayer
            {
                Version = HttpVersion.Version11,
                Header = new HttpHeader(new HttpContentLengthField(11)),
                Body = new Datagram(Encoding.ASCII.GetBytes(data)),
                Method = new HttpRequestMethod(HttpRequestKnownMethod.Get),
                Uri = Domain,
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
            listLayers.Add(httpLayer);
            AddLayers(listLayers);
            HTTPpacket = builder.Build(DateTime.Now);
        }
    }
}

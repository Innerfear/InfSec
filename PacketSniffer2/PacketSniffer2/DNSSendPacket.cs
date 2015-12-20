using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Transport;
using System;

namespace PacketSniffer2
{
    // This class builds a DNS over UDP over IPv4 over Ethernet packet.
    class DNSSendPacket : BaseSendPacket
    {
        private Packet DNSpacket;
        private UdpLayer udpLayer;
        private DnsLayer dnsLayer;
        public DNSSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL, string PORTsrc, string Identifier, string Domain)
        {
            GetBase(MACsrc, MACdst, IPsrc, IPdst, IpId, TTL);

            udpLayer = new UdpLayer
            {
                SourcePort = StringToUShort(PORTsrc),
                DestinationPort = 53,
                Checksum = null, // Will be filled automatically.
                CalculateChecksumValue = true,
            };

            dnsLayer = new DnsLayer
            {
                Id = StringToUShort(Identifier),
                IsResponse = false,
                OpCode = DnsOpCode.Query,
                IsAuthoritativeAnswer = false,
                IsTruncated = false,
                IsRecursionDesired = true,
                IsRecursionAvailable = false,
                FutureUse = false,
                IsAuthenticData = false,
                IsCheckingDisabled = false,
                ResponseCode = DnsResponseCode.NoError,
                Queries = new[] {
                    new DnsQueryResourceRecord(new DnsDomainName(Domain), DnsType.A, DnsClass.Internet),},
                Answers = null,
                Authorities = null,
                Additionals = null,
                DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
            };
        }

        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
            return DNSpacket = builder.Build(DateTime.Now);
        }
    }
}

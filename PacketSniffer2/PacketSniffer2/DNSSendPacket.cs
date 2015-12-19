using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;

namespace PacketSniffer2
{
    // This class builds a DNS over UDP over IPv4 over Ethernet packet.
    class DNSSendPacket : BaseSendPacket
    {
        private Packet DNSpacket;
        private IpV4Layer ipV4Layer;
        private UdpLayer udpLayer;
        private DnsLayer dnsLayer;
        public DNSSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL, string PORTsrc, string Identifier, string Domain)
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
                    Queries = new[]
                        {
                              new DnsQueryResourceRecord(
                                  new DnsDomainName(Domain),
                                  DnsType.A,
                                  DnsClass.Internet),
                        },
                    Answers = null,
                    Authorities = null,
                    Additionals = null,
                    DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                };
        }
        public override void GetBase(string MACsrc, string MACdst)
        {
            base.GetBase(MACsrc, MACdst);
        }

        public Packet GetBuilder()
        {
            builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);
            return DNSpacket = builder.Build(DateTime.Now);
        }
    }
}

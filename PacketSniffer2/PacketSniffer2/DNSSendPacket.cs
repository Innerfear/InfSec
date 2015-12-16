using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
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
    /// This class builds a DNS over UDP over IPv4 over Ethernet packet.
    /// </summary>
    class DNSSendPacket : BaseSendPacket
    {
        public Packet DNSpacket;
        protected IpV4Layer ipv4Layer;
        protected UdpLayer udpLayer;
        protected DnsLayer dnsLayer;
        public DNSSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string PORTsrc, string PORTdst, string Identifier, string Domain)
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

            UdpLayer udpLayer =
            new UdpLayer
            {
                SourcePort = StringToUShort(PORTsrc),
                DestinationPort = StringToUShort(PORTdst),
                Checksum = null, // Will be filled automatically.
                CalculateChecksumValue = true,
            };

            dnsLayer =
                new DnsLayer
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

        public void GetBuilder()
        {
            listLayers.Add(ethernetLayer);
            listLayers.Add(ipv4Layer);
            listLayers.Add(udpLayer);
            listLayers.Add(dnsLayer);
            AddLayers(listLayers);
            DNSpacket = builder.Build(DateTime.Now);
        }
    }
}

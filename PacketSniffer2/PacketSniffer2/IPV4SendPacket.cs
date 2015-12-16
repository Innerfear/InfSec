using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an IPv4 over Ethernet with payload packet.
    /// </summary>
    class IPV4SendPacket : BaseSendPacket
    {
        public Packet IPV4packet;
        protected IpV4Layer ipv4Layer;
        protected PayloadLayer payloadLayer;
        public IPV4SendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string data)
        {
            GetBase(MACsrc, MACdst);

            ipv4Layer = new IpV4Layer
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
            listLayers.Add(ethernetLayer);
            listLayers.Add(ipv4Layer);
            listLayers.Add(payloadLayer);
            AddLayers(listLayers);
            return IPV4packet = builder.Build(DateTime.Now);
        }
    }
}

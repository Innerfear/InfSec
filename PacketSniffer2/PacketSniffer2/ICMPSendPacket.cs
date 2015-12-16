using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketSniffer2
{
    /// <summary>
    /// This class builds an ICMP over IPv4 over Ethernet packet.
    /// </summary>
    class ICMPSendPacket : BaseSendPacket
    {
        public Packet ICMPpacket;
        protected IpV4Layer ipv4Layer;
        protected IcmpEchoLayer icmplayer;
        public ICMPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string Identifier, string SQN)
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

            icmplayer =
            new IcmpEchoLayer
            {
                Checksum = null, // Will be filled automatically.
                Identifier = StringToUShort(Identifier),
                SequenceNumber = StringToUShort(SQN),
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
            listLayers.Add(icmplayer);
            AddLayers(listLayers);
            ICMPpacket = builder.Build(DateTime.Now);
        }
    }
}

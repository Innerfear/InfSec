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
    /// This class builds an UDP over IPv4 over Ethernet with payload packet.
    /// </summary>
    class UDPSendPacket : BaseSendPacket
    {
        public Packet UPDpacket;
        protected IpV4Layer ipv4Layer;
        protected UdpLayer udpLayer;
        protected PayloadLayer payloadLayer;
        public UDPSendPacket(string MACsrc, string MACdst, string IPsrc, string IPdst, string IpId, string TTL, string PORTsrc, string PORTdst, string data)
        {
            GetBase(MACsrc, MACdst);

            //CODE HIER
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

           udpLayer =
           new UdpLayer
           {
               SourcePort = StringToUShort(PORTsrc),
               DestinationPort = StringToUShort(PORTdst),
               Checksum = null, // Will be filled automatically.
               CalculateChecksumValue = true,
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
            listLayers.Add(udpLayer);
            listLayers.Add(payloadLayer);
            AddLayers(listLayers);
            UPDpacket = builder.Build(DateTime.Now);
        }
    }
}

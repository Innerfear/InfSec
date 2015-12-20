using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;

namespace PacketSniffer2
{
    abstract class BaseSendPacket
    {
        protected EthernetLayer ethernetLayer;
        protected IpV4Layer ipV4Layer;
        protected PacketBuilder builder;

        public virtual void GetBase(string MACsrc, string MACdst, string IPsrc, string IPdst,
            string IpId, string TTL)
        {
            // Ethernet Layer
            ethernetLayer = new EthernetLayer
            {
                Source = new MacAddress(MACsrc),
                Destination = new MacAddress(MACdst),
                // Set ethernet type
                EtherType = EthernetType.None
            };

            // IpV4 Layer
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
        }

        public byte StringToByte(string sString)
        {
            byte newByte;
            if (sString != null)
            {
                newByte = byte.Parse(sString);
                return newByte;
            }
            else
            {
                return newByte = 1;
            }
        }

        public int StringToInt(string sString)
        {
            int newInt;
            if (sString != null)
            {
                newInt = int.Parse(sString);
                return newInt;
            }
            else
            {
                return newInt = 1;
            }
        }
        public ushort StringToUShort (string sString)
        {
            ushort newUShort;
            if (sString != null)
            {
                newUShort = ushort.Parse(sString);
                return newUShort;
            }
            else
            {
                return newUShort = 1;
            }
        }
    }
}

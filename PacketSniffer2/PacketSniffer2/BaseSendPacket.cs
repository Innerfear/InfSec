using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;

namespace PacketSniffer2
{
    abstract class BaseSendPacket
    {
        protected EthernetLayer ethernetLayer;
        protected PacketBuilder builder;
        /// <summary>
        /// Will hold all layers that are needed as input for the packet builder
        /// </summary>
        protected IList<ILayer> layers;

        public virtual void GetAdresses(string MACsrc, string MACdst)
        {
            // Supposing to be on ethernet, set mac source
            MacAddress source = new MacAddress(MACsrc);

            // Set mac destination
            MacAddress destination = new MacAddress(MACdst);

            // Create the packets layers

            // Ethernet Layer
            ethernetLayer = new EthernetLayer
            {
                Source = source,
                Destination = destination
                // The rest of the important parameters will be set for each packet
            };

            // Create the builder that will build our packets
            builder = new PacketBuilder(layers);

        }
        /// <summary>
        /// Add layers for builder
        /// </summary>
        public abstract void AddLayers();

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
    }

    /*
    class Packet : BaseSendPacket
    {

        public override void GetAdresses(string MACsrc, string MACdst)
        {
            base.GetAdresses(string MACsrc, string MACdst);
        }

        public override void AddLayers()
        {
            layers.Add(ethernetLayer);
        }
    }
    */
}

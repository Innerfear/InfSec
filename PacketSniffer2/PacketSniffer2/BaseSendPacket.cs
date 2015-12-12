﻿using System.Collections.Generic;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System.Collections;

namespace PacketSniffer2
{
    abstract class BaseSendPacket
    {
        protected EthernetLayer ethernetLayer;
        protected PacketBuilder builder;
        protected IList<ILayer> listLayers;
        /// <summary>
        /// Will hold all layers that are needed as input for the packet builder
        /// </summary>

        public virtual void GetBase(string MACsrc, string MACdst)
        {
            // Supposing to be on ethernet, set mac source
            MacAddress source = new MacAddress(MACsrc);

            // Set mac destination
            MacAddress destination = new MacAddress(MACdst);

            // Set ethernet type
            ethernetLayer.EtherType = EthernetType.None;

            // Create the packets layers

            // Ethernet Layer
            ethernetLayer = new EthernetLayer
            {
                Source = source,
                Destination = destination
                // The rest of the important parameters will be set for each packet
            };
        }
        /// <summary>
        /// Add layers for builder
        /// </summary>
        public void AddLayers(IList<ILayer> layers)
        {
            // Create the builder that will build our packets
            builder = new PacketBuilder(layers);
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
    }

    /*
    class Packet : BaseSendPacket
    {

        public override void GetBase(string MACsrc, string MACdst, ...)
        {
            base.GetAdresses(string MACsrc, string MACdst, ...);
        }

        public override void AddLayers()
        {
            layers.Add(ethernetLayer, ...);
        }
    }
    */
}

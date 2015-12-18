namespace PacketSniffer2
{
    public class PacketAPI
    {
        private string protocol;
        public string Protocol
        {
            get { return protocol; }
            set { protocol = value; }
        }

        private string ip;
        public string Ip
        {
            get { return ip; }
            set { ip = value; }
        }

        private string source;
        public string Source
        {
            get { return source; }
            set { source = value; }
        }

        private string destination;
        public string Destination
        {
            get { return destination; }
            set { destination = value; }
        }

        private string tcp;
        public string Tcp
        {
            get { return tcp; }
            set {
                if (value == null)
                {
                    value = "";
                }
                else
                tcp = value; }
        }

        private string header;
        public string Header
        {
            get { return header; }
            set { header = value; }
        }

        private int autonumber;
        public int Autonumber
        {
            get { return autonumber; }
            set { autonumber = value; }
        }

        private int length;
        public int Length
        {
            get { return length; }
            set { length = value; }
        }

        private string udp;
        public string Udp
        {
            get { return udp; }
            set { udp = value; }
        }   

        private string ipaddressS;
        public string IpaddressS
        {
            get { return ipaddressS; }
            set { ipaddressS = value; }
        }

        private string ipaddressD;
        public string IpaddressD
        {
            get { return ipaddressD; }
            set { ipaddressD = value; }
        }

        private string macaddressS;
        public string MacaddressS
        {
            get { return macaddressS; }
            set { macaddressS = value; }
        }

        private string macaddresD;
        public string MacaddressD
        {
            get { return macaddresD; }
            set { macaddresD = value; }
        }

        private int ttl;
        public int Ttl
        {
            get { return ttl; }
            set { ttl = value; }
        }

        private int npackets;
        public int Npackets
        {
            get { return npackets; }
            set { npackets = value; }
        }

        private string poortnummer;
        public string Poortnummer
        {
            get { return poortnummer; }
            set { poortnummer = value; }
        }

        private string payload;
        public string Payload
        {
            get { return payload; }
            set
            {
                if (value == null)
                {
                    value = "";
                }
                else
                    payload = value;
            }
        }

        private ushort vlan;
        public ushort Vlan
        {
            get { return vlan; }
            set { vlan = value; }
        }

        private ushort icmpIdentifier;
        public ushort IcmpIdentifier
        {
            get { return icmpIdentifier; }
            set { icmpIdentifier = value; }
        }

        private ushort icmpSequence;
        public ushort IcmpSequence
        {
            get { return icmpSequence; }
            set { icmpSequence = value; }
        }

        private byte[] arpSH;
        public byte[] ArpSH
        {
            get { return arpSH; }
            set { arpSH = value; }
        }

        private byte[] arpDH;
        public byte[] ArpDH
        {
            get { return arpDH; }
            set { arpDH = value; }
        }

    }
}

namespace PacketSniffer2
{
    public class PacketAPI
    {
        private int autonumber;
        public int Autonumber
        {
            get { return autonumber; }
            set { autonumber = value; }
        }

        private string protocol;
        public string Protocol
        {
            get { return protocol; }
            set { protocol = value; }
        }

        private bool ipv4;
        public bool Ipv4
        {
            get { return ipv4; }
            set { ipv4 = value; }
        }

        private bool icmp;
        public bool Icmp
        {
            get { return icmp; }
            set { icmp = value; }
        }

        private bool udp;
        public bool Udp
        {
            get { return udp; }
            set { udp = value; }
        }

        private bool tcp;
        public bool Tcp
        {
            get { return tcp; }
            set { tcp = value; }
        }

        private bool dns;
        public bool Dns
        {
            get { return dns; }
            set { dns = value; }
        }

        private bool http;
        public bool Http
        {
            get { return http; }
            set { http = value; }
        }

        private string ipsource;
        public string IpSource
        {
            get { return ipsource; }
            set { ipsource = value; }
        }

        private string ipdestination;
        public string IpDestination
        {
            get { return ipdestination; }
            set { ipdestination = value; }
        }






        private string header;
        public string Header
        {
            get { return header; }
            set { header = value; }
        }

        private int length;
        public int Length
        {
            get { return length; }
            set { length = value; }
        }

        private string macsource;
        public string MacSource
        {
            get { return macsource; }
            set { macsource = value; }
        }

        private string macdestination;
        public string MacDestination
        {
            get { return macdestination; }
            set { macdestination = value; }
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

        private string portnumber;
        public string Portnumber
        {
            get { return portnumber; }
            set { portnumber = value; }
        }

        private string payload;
        public string Payload
        {
            get { return payload; }
            set { payload = value; }
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

    }
}

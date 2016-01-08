namespace PacketSniffer2
{
    public class PacketAPI
    {
        private string timestamp;
        public string Timestamp
        {
            get { return timestamp; }
            set { timestamp = value; }
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

        private int length;
        public int Length
        {
            get { return length; }
            set { length = value; }
        }

        private int ttl;
        public int Ttl
        {
            get { return ttl; }
            set { ttl = value; }
        }

        private ushort portSource;
        public ushort PortSource
        {
            get { return portSource; }
            set { portSource = value; }
        }

        private ushort portDestination;
        public ushort PortDestination
        {
            get { return portDestination; }
            set { portDestination = value; }
        }

        private ushort id;
        public ushort Id
        {
            get { return id; }
            set { id = value; }
        }

        private ushort sqn;
        public ushort Sqn
        {
            get { return sqn; }
            set { sqn = value; }
        }

        private ushort ack;
        public ushort Ack
        {
            get { return ack; }
            set { ack = value; }
        }

        private ushort win;
        public ushort Win
        {
            get { return win; }
            set { win = value; }
        }
    }
}

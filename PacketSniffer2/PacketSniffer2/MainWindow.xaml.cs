using MahApps.Metro.Controls;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace PacketSniffer2
{
    // Interaction logic for MainWindow.xaml
    public partial class MainWindow : MetroWindow
    {
        // All variables
        #region Variables
        //Bool variables
        bool bIPV4Check = false;
        bool bIcmpCheck = false;
        bool bUdpCheck = false;
        bool bTcpCheck = false;
        bool bDnsCheck = false;
        bool bHttpCheck = false;

        bool bRefreshed = false;

        //bool bCapture = false;
        //bool bEdit = false;

        //Packet variables
        PacketAPI pInfoPacket;
        PacketDevice pSelectedDevice;
        PacketCommunicator pCommunicator;

        DNSSendPacket pBuildDnsPacket;
        TCPSendPacket pBuildTcpPacket;
        UDPSendPacket pBuildUdpPacket;
        ICMPSendPacket pBuildIcmpPacket;
        HTTPSendPacket pBuildHttpPacket;

        //Thread variables
        Thread tCapture;
        //Thread tEdit;

        //Misc variables
        IList<LivePacketDevice> listAllDevices;
        public delegate void UpdateTextCallback(PacketAPI message);
        public ObservableCollection<PacketAPI> ocPackets = new ObservableCollection<PacketAPI>();
        ManualResetEvent eShutdown = new ManualResetEvent(false);
        ManualResetEvent ePause = new ManualResetEvent(true);
        #endregion

        // All initialization methods / definitions
        #region Initialization
        public MainWindow()
        {
            InitializeComponent();

            Width = SystemParameters.WorkArea.Width;
            Height = SystemParameters.WorkArea.Height;
            Top = SystemParameters.WorkArea.Top;
            Left = SystemParameters.WorkArea.Left;
        }

        #endregion

        // All methods that don't handle initialization
        #region Methods

        #region Startup Methods
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            GetDevices();
        }

        private void MetroWindow_Closed(object sender, System.EventArgs e)
        {
            tCapture.Abort();
        }
        
        private void GetDevices()
        {
            listAllDevices = LivePacketDevice.AllLocalMachine;

            if (listAllDevices.Count == 0)
            {
                DeviceListBox.Items.Add("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != listAllDevices.Count; ++i)
            {
                LivePacketDevice device = listAllDevices[i];
                if (device.Description != null)
                    DeviceListBox.Items.Add((i + 1) + ". " + device.Name + " (" + device.Description + ")");
                else
                    DeviceListBox.Items.Add((i + 1) + ". " + device.Name + " (No description available)");
            }
        }

        // Print all the available information on the given interface
        private void DevicePrint(IPacketDevice device)
        {
            // Name
            DeviceInfo.Items.Add(device.Name);

            // Description
            if (device.Description != null)
                DeviceInfo.Items.Add("     Description: " + device.Description);

            // Loopback Address
            DeviceInfo.Items.Add("     Loopback: " +
                              (((device.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback)
                                   ? "yes"
                                   : "no"));

            // IP addresses
            foreach (DeviceAddress address in device.Addresses)
            {
                DeviceInfo.Items.Add("     Address Family: " + address.Address.Family);

                if (address.Address != null)
                    DeviceInfo.Items.Add(("\tAddress: " + address.Address));
                if (address.Netmask != null)
                    DeviceInfo.Items.Add(("\tNetmask: " + address.Netmask));
                if (address.Broadcast != null)
                    DeviceInfo.Items.Add(("\tBroadcast Address: " + address.Broadcast));
                if (address.Destination != null)
                    DeviceInfo.Items.Add(("\tDestination Address: " + address.Destination));
            }
        }

        private void GetSelectedDevice()
        {
            for (int i = 0; i != listAllDevices.Count; ++i)
            {
                LivePacketDevice device = listAllDevices[i];
                if (DeviceListBox.SelectedItem.ToString() != null)
                {
                    if (DeviceListBox.SelectedItem.ToString().Contains(device.Name))
                    {
                        pSelectedDevice = device;
                        PacketList.ItemsSource = ocPackets;
                    }
                }
                else
                {
                    MessageBox.Show("Select a device and press 'capture' to start.");
                }
            }
        }
        #endregion

        #region Sniffing Methods
        private void PacketHandler(Packet packet)
        {
            var ArrivedPacket = new PacketAPI();

            ArrivedPacket.Timestamp = packet.Timestamp.ToString();
            ArrivedPacket.MacSource = packet.Ethernet.Source.ToString();
            ArrivedPacket.MacDestination = packet.Ethernet.Destination.ToString();
            ArrivedPacket.IpSource = packet.Ethernet.IpV4.Source.ToString();
            ArrivedPacket.IpDestination = packet.Ethernet.IpV4.Destination.ToString();
            ArrivedPacket.Length = packet.Length;
            ArrivedPacket.Ttl = packet.Ethernet.IpV4.Ttl;
            ArrivedPacket.Id = packet.Ethernet.IpV4.Identification;

            if (packet.Ethernet.EtherType == EthernetType.IpV4)
            {
                ArrivedPacket.Ipv4 = true;
                ArrivedPacket.Protocol = "IPV4";
                if (packet.Ethernet.IpV4.Icmp != null && packet.Ethernet.IpV4.Protocol.ToString() == "InternetControlMessageProtocol")
                {
                    ArrivedPacket.Icmp = true;
                    ArrivedPacket.Protocol = "ICMP";
                }
                else
                {
                    ArrivedPacket.Icmp = false;
                }

                if (packet.Ethernet.IpV4.Udp != null && packet.Ethernet.IpV4.Protocol.ToString() == "Udp")
                {
                    ArrivedPacket.Udp = true;
                    ArrivedPacket.Protocol = "UDP";
                    ArrivedPacket.PortSource = packet.Ethernet.IpV4.Udp.SourcePort;
                    ArrivedPacket.PortDestination = packet.Ethernet.IpV4.Udp.DestinationPort;
                    if (ArrivedPacket.PortDestination == 53 || ArrivedPacket.PortDestination > 1023 
                        || ArrivedPacket.PortSource == 53 || ArrivedPacket.PortSource > 1023)
                    {
                        ArrivedPacket.Dns = true;
                        ArrivedPacket.Protocol = "DNS";
                    }
                    else
                    {
                        ArrivedPacket.Dns = false;
                    }
                }
                else
                {
                    ArrivedPacket.Udp = false;
                }

                if (packet.Ethernet.IpV4.Tcp != null && packet.Ethernet.IpV4.Protocol.ToString() == "Tcp")
                {
                    ArrivedPacket.Tcp = true;
                    ArrivedPacket.Protocol = "TCP";
                    ArrivedPacket.PortSource = packet.Ethernet.IpV4.Tcp.SourcePort;
                    ArrivedPacket.PortDestination = packet.Ethernet.IpV4.Tcp.DestinationPort;
                    if (ArrivedPacket.PortDestination == 80 || ArrivedPacket.PortSource == 80)
                    {
                        ArrivedPacket.Http = true;
                        ArrivedPacket.Protocol = "HTTP";
                    }
                    else
                    {
                        ArrivedPacket.Http = false;
                    }
                }
                else
                {
                    ArrivedPacket.Tcp = false;
                }
            }
            else
            {
                ArrivedPacket.Ipv4 = false;
            }

            if (bIcmpCheck && ArrivedPacket.Icmp)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (bUdpCheck && ArrivedPacket.Udp)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (bTcpCheck && ArrivedPacket.Tcp)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (bDnsCheck && ArrivedPacket.Dns)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (bHttpCheck && ArrivedPacket.Http)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (bIPV4Check && ArrivedPacket.Ipv4)
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
        }

        private void StartThreadAnalyze()
        {
            Dispatcher.Invoke((ThreadStart)delegate { pSelectedDevice.ToString(); },
                DispatcherPriority.Normal, null);

            if (pSelectedDevice.ToString() != null)
            {
                while (true)
                {
                    ePause.WaitOne(Timeout.Infinite);   // 
                    if (eShutdown.WaitOne(0))           // wrs redundant
                        break;                          //

                    //bCapture = true;
                    using (PacketCommunicator communicator = pSelectedDevice.Open(65536,
                        PacketDeviceOpenAttributes.Promiscuous, 1000))
                    {
                        communicator.ReceivePackets(0, PacketHandler);
                    }
                    //bCapture = false;
                }
            }
            else
                MessageBox.Show("Please choose a networkadapter");
        }

        private void UpdatePacketText(PacketAPI packet)
        {
            ocPackets.Add(packet);
        }

        private void btnStartCap_Click(object sender, RoutedEventArgs e)
        {
            DeviceRefresh.IsEnabled = false;
            btnStartCap.IsEnabled = false;
            btnStopCap.IsEnabled = true;
            DeviceListBox.IsEnabled = false;
            DeviceInfo.Items.Clear();
            DeviceListBox.Visibility = Visibility.Hidden;
            PacketInfo.Visibility = Visibility.Visible;
            DeviceInfo.Visibility = Visibility.Hidden;
            PacketList.Visibility = Visibility.Visible;

            tCapture = new Thread(new ThreadStart(StartThreadAnalyze));
            tCapture.Start();
        }

        private void btnStartEdit_Click(object sender, RoutedEventArgs e)
        {
            PacketAPI editablePacket = (PacketAPI)PacketList.SelectedItem;

            switch (editablePacket.Protocol)
            {
                case "ICMP":
                    ProtType.SelectedIndex = 1;
                    break;
                case "UDP":
                    ProtType.SelectedIndex = 2;
                    break;
                case "TCP":
                    ProtType.SelectedIndex = 3;
                    break;
                case "DNS":
                    ProtType.SelectedIndex = 4;
                    break;
                case "HTTP":
                    ProtType.SelectedIndex = 5;
                    break;
            }

            MACsrc.Text = editablePacket.MacSource;
            MACdst.Text = editablePacket.MacDestination;
            IPsrc.Text = editablePacket.IpSource;
            IPdst.Text = editablePacket.IpDestination;
            IpId.Text = editablePacket.Id.ToString();
            TTL.Text = editablePacket.Ttl.ToString();
            PORTsrc.Text = editablePacket.PortSource.ToString();

        }

        private void btnStopCap_Click(object sender, RoutedEventArgs e)
        {
            DeviceRefresh.IsEnabled = true;
            btnStartCap.IsEnabled = true;
            btnStopCap.IsEnabled = false;
            DeviceListBox.IsEnabled = true;

            tCapture.Abort();
        }

        private void DeviceRefresh_Click(object sender, RoutedEventArgs e)
        {
            bRefreshed = true;
            DeviceListBox.Items.Clear();
            PacketList.ItemsSource = null;
            PacketList.Items.Clear();
            DeviceInfo.Visibility = Visibility.Visible;
            PacketList.Visibility = Visibility.Hidden;
            DeviceListBox.Visibility = Visibility.Visible;
            PacketInfo.Visibility = Visibility.Hidden;
            GetDevices();
        }
        private void DeviceListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            DeviceInfo.Items.Clear();
            DeviceInfo.Visibility = Visibility.Visible;
            PacketList.Visibility = Visibility.Hidden;
            DeviceListBox.Visibility = Visibility.Visible;
            PacketInfo.Visibility = Visibility.Hidden;
            btnStartCap.IsEnabled = true;
            if (!bRefreshed)
            {
                GetSelectedDevice();
                DevicePrint(pSelectedDevice);
            }
            bRefreshed = false;
        }

        private void CheckBoxFalse()
        {
            bIPV4Check = false;
            bIcmpCheck = false;
            bUdpCheck = false;
            bTcpCheck = false;
            bDnsCheck = false;
            bHttpCheck = false;
        }

        private void rbIPV4_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bIPV4Check = true;
        }

        private void rbICMP_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bIcmpCheck = true;
        }

        private void rbUDP_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bUdpCheck = true;
        }

        private void rbTCP_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bTcpCheck = true;
        }

        private void rbDNS_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bDnsCheck = true;
        }

        private void rbHTTP_Checked(object sender, RoutedEventArgs e)
        {
            CheckBoxFalse();
            bHttpCheck = true;
        }

        private void PacketList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            PacketInfo.Items.Clear();
            btnStartEdit.IsEnabled = true;
            pInfoPacket = new PacketAPI();
            pInfoPacket = (PacketAPI)PacketList.SelectedItems[0];

            PacketInfo.Items.Add("Time Of Arrival: " + pInfoPacket.Timestamp);

            if (pInfoPacket.Http)
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / TCP / HTTP");
            else if (pInfoPacket.Dns)
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / UDP / DNS");
            else if (pInfoPacket.Tcp)
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / TCP");
            else if (pInfoPacket.Udp)
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / UDP");
            else if (pInfoPacket.Icmp)
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / ICMP");
            else
                PacketInfo.Items.Add("Protocol encapsulation: IPV4 / Unknown");

            PacketInfo.Items.Add("MAC Source: " + pInfoPacket.MacSource + "\tMAC Destination: " + pInfoPacket.MacDestination);
            PacketInfo.Items.Add("IP Source: " + pInfoPacket.IpSource + "\t\tIP Destination: " + pInfoPacket.IpDestination);
            PacketInfo.Items.Add("Length: " + pInfoPacket.Length + "\t\t\tTTL: " + pInfoPacket.Ttl + "\t\t\tID: " + pInfoPacket.Id);
            PacketInfo.Items.Add("Source Port: " + pInfoPacket.PortSource + "\t\t\tDestination Port: " + pInfoPacket.PortDestination);
        }
        #endregion
        /*
        #region Editing Methods

        #endregion
        */
        #region Injecting Methods
        private void btnSendPacket_Click(object sender, RoutedEventArgs e)
        {
            // Open the output device
            using (pCommunicator = pSelectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                int stringProtocol = ProtType.SelectedIndex;
                switch (stringProtocol)
                {
                    case 1:
                        if (MACsrc.Text != "" && MACdst.Text != "" && IPsrc.Text != "" && IPdst.Text != "" && IpId.Text != ""
                            && TTL.Text != "" && Identifier.Text != "" && SQN.Text != "")
                        {
                            pBuildIcmpPacket = new ICMPSendPacket(MACsrc.Text, MACdst.Text, IPsrc.Text,
                            IPdst.Text, IpId.Text, TTL.Text, Identifier.Text, SQN.Text);
                            pCommunicator.SendPacket(pBuildIcmpPacket.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    case 2:
                        if (MACsrc.Text != "" && MACdst.Text != "" && IPsrc.Text != "" && IPdst.Text != "" && IpId.Text != ""
                            && TTL.Text != "" && PORTsrc.Text != "" && Data.Text != "")
                        {
                            pBuildUdpPacket = new UDPSendPacket(MACsrc.Text, MACdst.Text, IPsrc.Text,
                            IPdst.Text, IpId.Text, TTL.Text, PORTsrc.Text, Data.Text);
                            pCommunicator.SendPacket(pBuildUdpPacket.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    case 3:
                        if (MACsrc.Text != "" && MACdst.Text != "" && IPsrc.Text != "" && IPdst.Text != "" && IpId.Text != "" && TTL.Text != ""
                            && PORTsrc.Text != "" && SQN.Text != "" && ACK.Text != "" && WIN.Text != "" && Data.Text != "")
                        {
                            pBuildTcpPacket = new TCPSendPacket(MACsrc.Text, MACdst.Text, IPsrc.Text, IPdst.Text,
                            IpId.Text, TTL.Text, PORTsrc.Text, SQN.Text, ACK.Text, WIN.Text, Data.Text);
                            pCommunicator.SendPacket(pBuildTcpPacket.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    case 4:
                        if (MACsrc.Text != "" && MACdst.Text != "" && IPsrc.Text != "" && IPdst.Text != "" && IpId.Text != "" && TTL.Text != ""
                            && PORTsrc.Text != "" && Identifier.Text != "" && Domain.Text != "")
                        {
                            pBuildDnsPacket = new DNSSendPacket(MACsrc.Text, MACdst.Text, IPsrc.Text, IPdst.Text,
                            IpId.Text, TTL.Text, PORTsrc.Text, Identifier.Text, Domain.Text);
                            pCommunicator.SendPacket(pBuildDnsPacket.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    case 5:
                        if (MACsrc.Text != "" && MACdst.Text != "" && IPsrc.Text != "" && IPdst.Text != "" && IpId.Text != "" && TTL.Text != ""
                            && PORTsrc.Text != "" && SQN.Text != "" && ACK.Text != "" && WIN.Text != "" && Data.Text != "" && Domain.Text != "")
                        {
                            pBuildHttpPacket = new HTTPSendPacket(MACsrc.Text, MACdst.Text, IPsrc.Text, IPdst.Text, IpId.Text,
                            TTL.Text, PORTsrc.Text, SQN.Text, ACK.Text, WIN.Text, Data.Text, Domain.Text);
                            pCommunicator.SendPacket(pBuildHttpPacket.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    default:
                        MessageBox.Show("Select a protocol");
                        break;
                }
            }
        }

        private void ProtType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            int stringProtocol = ProtType.SelectedIndex;
            switch (stringProtocol)
            {
                case 0:
                    if (MACsrc != null)
                    {
                        btnSendPacket.IsEnabled = false;
                        MACsrc.IsEnabled = false;
                        MACsrc.Text = "";
                        MACdst.IsEnabled = false;
                        MACdst.Text = "";
                        IPsrc.IsEnabled = false;
                        IPsrc.Text = "";
                        IPdst.IsEnabled = false;
                        IPdst.Text = "";
                        IpId.IsEnabled = false;
                        IpId.Text = "";
                        TTL.IsEnabled = false;
                        TTL.Text = "";
                        Data.IsEnabled = false;
                        Data.Text = "";
                        Identifier.IsEnabled = false;
                        Identifier.Text = "";
                        PORTsrc.IsEnabled = false;
                        PORTsrc.Text = "";
                        SQN.IsEnabled = false;
                        SQN.Text = "";
                        ACK.IsEnabled = false;
                        ACK.Text = "";
                        WIN.IsEnabled = false;
                        WIN.Text = "";
                        Domain.IsEnabled = false;
                        Domain.Text = "";
                    }
                    break;
                case 1:
                    Data.IsEnabled = false;
                    Data.Text = "";
                    Identifier.IsEnabled = true;
                    PORTsrc.IsEnabled = false;
                    PORTsrc.Text = "";
                    SQN.IsEnabled = true;
                    SQN.Text = "";
                    ACK.IsEnabled = false;
                    ACK.Text = "";
                    WIN.IsEnabled = false;
                    WIN.Text = "";
                    Domain.IsEnabled = false;
                    Domain.Text = "";
                    goto case 100;
                case 2:
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    Identifier.Text = "";
                    PORTsrc.IsEnabled = true;
                    SQN.IsEnabled = false;
                    SQN.Text = "";
                    ACK.IsEnabled = false;
                    ACK.Text = "";
                    WIN.IsEnabled = false;
                    WIN.Text = "";
                    Domain.IsEnabled = false;
                    Domain.Text = "";
                    goto case 100;
                case 3:
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    Identifier.Text = "";
                    PORTsrc.IsEnabled = true;
                    SQN.IsEnabled = true;
                    ACK.IsEnabled = true;
                    WIN.IsEnabled = true;
                    Domain.IsEnabled = false;
                    Domain.Text = "";
                    goto case 100;
                case 4:
                    Data.IsEnabled = false;
                    Data.Text = "";
                    Identifier.IsEnabled = true;
                    PORTsrc.IsEnabled = true;
                    SQN.IsEnabled = false;
                    SQN.Text = "";
                    ACK.IsEnabled = false;
                    ACK.Text = "";
                    WIN.IsEnabled = false;
                    WIN.Text = "";
                    Domain.IsEnabled = true;
                    goto case 100;
                case 5:
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    Identifier.Text = "";
                    PORTsrc.IsEnabled = true;
                    SQN.IsEnabled = true;
                    ACK.IsEnabled = true;
                    WIN.IsEnabled = true;
                    Domain.IsEnabled = true;
                    goto case 100;
                case 100:
                    MACsrc.IsEnabled = true;
                    MACdst.IsEnabled = true;
                    IPsrc.IsEnabled = true;
                    IPdst.IsEnabled = true;
                    IpId.IsEnabled = true;
                    TTL.IsEnabled = true;
                    btnSendPacket.IsEnabled = true;
                    break;
            }
        }
        #endregion

        #endregion
    }
}

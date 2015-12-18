using PcapDotNet.Core;
using PcapDotNet.Packets;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;

namespace PacketSniffer2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        #region Variables
        //Bool variables
        bool bFullScreen = true;

        bool bCapture = false;
        bool bInject = false;
        bool bEdit = false;

        //Packet variables
        PacketDevice pSelectedDevice;
        PacketCommunicator pCommunicator;

        DNSSendPacket pBuildDnsPacket;
        TCPSendPacket pBuildTcpPacket;
        UDPSendPacket pBuildUdpPacket;
        ICMPSendPacket pBuildIcmpPacket;
        IPV4SendPacket pBuildIpV4Packet;
        HTTPSendPacket pBuildHttpPacket;

        //Thread variables
        Thread tCapture;
        Thread tInject;
        Thread tEdit;

        //Misc variables
        IList<LivePacketDevice> listAllDevices = LivePacketDevice.AllLocalMachine;
        public delegate void UpdateTextCallback(PacketAPI message);
        public ObservableCollection<PacketAPI> ocPackets = new ObservableCollection<PacketAPI>();
        ManualResetEvent eShutdown = new ManualResetEvent(false);
        ManualResetEvent epause = new ManualResetEvent(true);
        #endregion

        #region Initialization
        public MainWindow()
        {
            InitializeComponent();

            Width = SystemParameters.WorkArea.Width;
            Height = SystemParameters.WorkArea.Height;
            Top = SystemParameters.WorkArea.Top;
            Left = SystemParameters.WorkArea.Left;

            PacketList.ItemsSource = ocPackets;
        }
        #endregion

        #region Methods
        /*
        private void StartNpfService()
        {
            Process Npf = new Process();
            var NpfInfo = new ProcessStartInfo();
            NpfInfo.WindowStyle = ProcessWindowStyle.Hidden;
            NpfInfo.WorkingDirectory = @"C:\Windows\System32";
            NpfInfo.FileName = @"C:\Windows\System32\cmd.exe";
            NpfInfo.Verb = "runas";
            NpfInfo.Arguments = "/C sc start npf";
            Npf.StartInfo = NpfInfo;
            Npf.Start();
        }
        */

        private void PacketHandler(Packet packet)
        {
            var ArrivedPacket = new PacketAPI();

            ArrivedPacket.Autonumber = PacketList.Items.Count;

            ArrivedPacket.Protocol = packet.Ethernet.EtherType.ToString();
            //  ArrivedPacket.Protocol = packet.DataLink.ToString();
            ArrivedPacket.Source = packet.Ethernet.IpV4.Source.ToString();
            ArrivedPacket.Destination = packet.Ethernet.IpV4.Destination.ToString();
            if (packet.Ethernet.IpV4.Udp != null)
            {
                ArrivedPacket.Udp = packet.Ethernet.IpV4.Udp.ToString();
            }
            else
            {
                ArrivedPacket.Udp = "None";
            }
            if (packet.Ethernet.IpV4.Tcp != null)
            {
                ArrivedPacket.Poortnummer = packet.Ethernet.IpV4.Tcp.SourcePort.ToString();
                ArrivedPacket.Header = packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber.ToString();
                ArrivedPacket.Tcp = packet.Ethernet.IpV4.Tcp.ToString();
            }
            else
            {
                ArrivedPacket.Tcp = "No details";
                ArrivedPacket.Length = packet.Length;
            }
            /*
            if (Arpfilter && ArrivedPacket.Protocol == "Arp")
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (Ipv4Filter && ArrivedPacket.Protocol == "IpV4")
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (Ipv6Filter && ArrivedPacket.Protocol == "IpV6")
                Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
            else if (filternone)
            */
            Dispatcher.Invoke(new UpdateTextCallback(UpdatePacketText), ArrivedPacket);
        }

        private void UpdatePacketText(PacketAPI packet)
        {
            ocPackets.Add(packet);
        }

        private void GetDevices()
        {
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
                    DeviceListBox.Items.Add((i + 1) + ". " + device.Name + " (" + device.Description+ ")");
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
                    }
                }
                else
                {
                    MessageBox.Show("Select a device and press 'capture' to start.");
                }     
            }
        }
        #endregion

        #region XAML activated methods
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            GetDevices();
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void HalfSizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (bFullScreen)
                Width = SystemParameters.WorkArea.Width / 2;
            bFullScreen = false;
            HalfSizeButton.IsEnabled = false;
            FullSizeButton.IsEnabled = true;
        }

        private void FullSizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (!bFullScreen)
                Width = SystemParameters.WorkArea.Width;
            bFullScreen = true;
            FullSizeButton.IsEnabled = false;
            HalfSizeButton.IsEnabled = true;
        }

        private void StartCap_Click(object sender, RoutedEventArgs e)
        {
            DeviceRefresh.IsEnabled = false;
            StartCap.IsEnabled = false;
            DeviceListBox.IsEnabled = false;
            DeviceInfo.Items.Clear();
            DeviceInfo.Visibility = Visibility.Hidden;
            PacketList.Visibility = Visibility.Visible;
        }

        private void StopCap_Click(object sender, RoutedEventArgs e)
        {
            DeviceRefresh.IsEnabled = true;
            StartCap.IsEnabled = true;
            DeviceListBox.IsEnabled = true;
        }

        private void DeviceRefresh_Click(object sender, RoutedEventArgs e)
        {
            DeviceListBox.Items.Clear();
            PacketList.Items.Clear();
            DeviceInfo.Visibility = Visibility.Visible;
            PacketList.Visibility = Visibility.Hidden;
            GetDevices();
        }

        private void DeviceListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            DeviceInfo.Items.Clear();
            DeviceInfo.Visibility = Visibility.Visible;
            PacketList.Visibility = Visibility.Hidden;
            GetSelectedDevice();
            DevicePrint(pSelectedDevice);
        }

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
                            && TTL.Text != "" && Data.Text != "")
                        {
                            pBuildIpV4Packet = new IPV4SendPacket(MACsrc.Text, MACdst.Text,
                                IPsrc.Text, IPdst.Text, IpId.Text, TTL.Text, Data.Text);
                            pCommunicator.SendPacket(pBuildIpV4Packet.GetBuilder());
                        }
                        else
                        {
                            MessageBox.Show("Please fill in all required (open) fields");
                        }
                        break;
                    case 2:
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
                    case 3:
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
                    case 4:
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
                    case 5:
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
                    case 6:
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
                    Data.IsEnabled = true;
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
                    goto case 100;
                case 2:
                    Data.IsEnabled = false;
                    Data.Text = "";
                    Identifier.IsEnabled = true;
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
                    goto case 100;
                case 3:
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
                case 4:
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
                case 5:
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
                case 6:
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
    }
}

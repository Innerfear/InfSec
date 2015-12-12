using PcapDotNet.Core;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

namespace PacketSniffer2
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        bool boolFullScreen = true;

        PacketDevice miscSelectedDevice;
        PacketCommunicator miscCommunicator;

        DNSSendPacket BuildDnsPacket;
        TCPSendPacket BuildTcpPacket;
        UDPSendPacket BuildUdpPacket;
        ICMPSendPacket BuildIcmpPacket;
        IPV4SendPacket BuildIpV4Packet;
        HTTPSendPacket BuildHttpPacket;

        // Retrieve the device list from the local machine
        IList<LivePacketDevice> listAllDevices = LivePacketDevice.AllLocalMachine;

        public MainWindow()
        {
            InitializeComponent();
            Width = SystemParameters.WorkArea.Width;
            Height = SystemParameters.WorkArea.Height;
            Top = SystemParameters.WorkArea.Top;
            Left = SystemParameters.WorkArea.Left;
        }
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
            PacketList.Items.Add(device.Name);

            // Description
            if (device.Description != null)
                PacketList.Items.Add("     Description: " + device.Description);

            // Loopback Address
            PacketList.Items.Add("     Loopback: " +
                              (((device.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback)
                                   ? "yes"
                                   : "no"));

            // IP addresses
            foreach (DeviceAddress address in device.Addresses)
            {
                PacketList.Items.Add("     Address Family: " + address.Address.Family);

                if (address.Address != null)
                    PacketList.Items.Add(("\tAddress: " + address.Address));
                if (address.Netmask != null)
                    PacketList.Items.Add(("\tNetmask: " + address.Netmask));
                if (address.Broadcast != null)
                    PacketList.Items.Add(("\tBroadcast Address: " + address.Broadcast));
                if (address.Destination != null)
                    PacketList.Items.Add(("\tDestination Address: " + address.Destination));
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
                        miscSelectedDevice = device;
                    }
                }     
            }
        }

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
            if (boolFullScreen)
                Width = SystemParameters.WorkArea.Width / 2;
            boolFullScreen = false;
            HalfSizeButton.IsEnabled = false;
            FullSizeButton.IsEnabled = true;
        }

        private void FullSizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (!boolFullScreen)
                Width = SystemParameters.WorkArea.Width;
            boolFullScreen = true;
            FullSizeButton.IsEnabled = false;
            HalfSizeButton.IsEnabled = true;
        }

        private void StartCap_Click(object sender, RoutedEventArgs e)
        {
            PacketList.Items.Clear();
        }

        private void StopCap_Click(object sender, RoutedEventArgs e)
        {

        }

        private void DeviceRefresh_Click(object sender, RoutedEventArgs e)
        {
            DeviceListBox.Items.Clear();
            GetDevices();
        }

        private void DeviceListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            PacketList.Items.Clear();
            GetSelectedDevice();
            DevicePrint(miscSelectedDevice);
        }

        private void btnSendPacket_Click(object sender, RoutedEventArgs e)
        {
            // Open the output device
            using (miscCommunicator = miscSelectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                string stringProtocol = ProtType.SelectedItem.ToString();
                switch (stringProtocol)
                {
                    case "IPV4":
                        BuildIpV4Packet = new IPV4SendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildIpV4Packet.GetBuilder();
                        miscCommunicator.SendPacket(BuildIpV4Packet.IPV4packet);
                        break;
                    case "ICMP":
                        BuildIcmpPacket = new ICMPSendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildIcmpPacket.GetBuilder();
                        miscCommunicator.SendPacket(BuildIcmpPacket.ICMPpacket);
                        break;
                    case "UDP":
                        BuildUdpPacket = new UDPSendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildUdpPacket.GetBuilder();
                        miscCommunicator.SendPacket(BuildUdpPacket.UPDpacket);
                        break;
                    case "TCP":
                        BuildTcpPacket = new TCPSendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildTcpPacket.GetBuilder();
                        miscCommunicator.SendPacket(BuildTcpPacket.TCPpacket);
                        break;
                    case "DNS":
                        BuildDnsPacket = new DNSSendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildDnsPacket.GetBuilder();
                        miscCommunicator.SendPacket(BuildDnsPacket.DNSpacket);
                        break;
                    case "HTTP":
                        BuildHttpPacket = new HTTPSendPacket(MACsrc.ToString(), MACdst.ToString());
                        BuildHttpPacket.GetBuilder();
                        miscCommunicator.SendPacket(BuildHttpPacket.HTTPpacket);
                        break;
                    default:
                        MessageBox.Show("Select a protocol");
                        break;        
                }
            }
        }

        private void ProtType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            string stringProtocol = ProtType.SelectedItem.ToString();
            switch (stringProtocol)
            {
                case "Standard":
                    MACsrc.IsEnabled = true;
                    MACdst.IsEnabled = true;
                    IPsrc.IsEnabled = true;
                    IPdst.IsEnabled = true;
                    IpId.IsEnabled = true;
                    TTL.IsEnabled = true;
                    break;
                case "IPV4":
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    PORTsrc.IsEnabled = false;
                    PORTdst.IsEnabled = false;
                    SQN.IsEnabled = false;
                    ACK.IsEnabled = false;
                    WIN.IsEnabled = false;
                    Domain.IsEnabled = false;
                    goto case "Standard";
                case "ICMP":
                    Data.IsEnabled = false;
                    Identifier.IsEnabled = true;
                    PORTsrc.IsEnabled = false;
                    PORTdst.IsEnabled = false;
                    SQN.IsEnabled = true;
                    ACK.IsEnabled = false;
                    WIN.IsEnabled = false;
                    Domain.IsEnabled = false;
                    goto case "Standard";
                case "UDP":
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    PORTsrc.IsEnabled = true;
                    PORTdst.IsEnabled = true;
                    SQN.IsEnabled = false;
                    ACK.IsEnabled = false;
                    WIN.IsEnabled = false;
                    Domain.IsEnabled = false;
                    goto case "Standard";
                case "TCP":
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    PORTsrc.IsEnabled = true;
                    PORTdst.IsEnabled = true;
                    SQN.IsEnabled = true;
                    ACK.IsEnabled = true;
                    WIN.IsEnabled = true;
                    Domain.IsEnabled = false;
                    goto case "Standard";
                case "DNS":
                    Data.IsEnabled = false;
                    Identifier.IsEnabled = true;
                    PORTsrc.IsEnabled = true;
                    PORTdst.IsEnabled = true;
                    SQN.IsEnabled = false;
                    ACK.IsEnabled = false;
                    WIN.IsEnabled = false;
                    Domain.IsEnabled = true;
                    goto case "Standard";
                case "HTTP":
                    Data.IsEnabled = true;
                    Identifier.IsEnabled = false;
                    PORTsrc.IsEnabled = true;
                    PORTdst.IsEnabled = true;
                    SQN.IsEnabled = true;
                    ACK.IsEnabled = true;
                    WIN.IsEnabled = true;
                    Domain.IsEnabled = true;
                    goto case "Standard";
            }
        }
    }
}

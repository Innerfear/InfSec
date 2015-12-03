using System;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Forms;
using System.Net;
using System.Windows.Controls;
using System.Diagnostics;

namespace PacketSniffer
{
    // Enum om Protocol te definiëren.
    public enum Protocol                                    
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // De socket die alle inkomende packets captured.
        private Socket mainSocket;                          
        private byte[] byteData = new byte[4096];
        // Een flag om te controleren of packets gecaptured worden of niet.
        private bool bGaDoorMetCapturen = false;
        private bool bFullScreen = true;

        private delegate void AddTreeItem(TreeViewItem item);

        public MainWindow()
        {
            InitializeComponent();

            // Set windowsize to maximum
            Width = SystemParameters.WorkArea.Width;
            Height = SystemParameters.WorkArea.Height;
            Top = SystemParameters.WorkArea.Top;
            Left = SystemParameters.WorkArea.Left;
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (lbInterfaces.SelectedItem == null)
            {
                System.Windows.Forms.MessageBox.Show("Selecteer een interface om pakketen te kunnen capturen.", "PacketSniffer",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                if (!bGaDoorMetCapturen)                    
                {
                    // Start het capturen van packets.
                    btnStart.Content = "Stop";
                    bGaDoorMetCapturen = true;
                    // Om te packets te kunnen capturen via de socket, moet de socket een raw socket zijn met adresfamilie: internetwork en protocol: IP.
                    mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                    // Bind de socket aan het geselecteerde IP address.
                    mainSocket.Bind(new IPEndPoint(IPAddress.Parse(lbInterfaces.SelectedItem.ToString()), 0));
                    // Stel socket options in. Geldt enkel voor de IP packets, header bijvoegen.
                    mainSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    // Capture uitgaande packets.
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 };

                    // Socket.IOControl is analoog aan de werkwijze WSAIoctl Winsock 2. Equivalent van SIO_RCVALL constante van Winsock 2.
                    mainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
                    // Start asynchroon ontvangen van packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                }
                else
                {
                    btnStart.Content = "Start";
                    bGaDoorMetCapturen = false;
                    // Stop capturen van packets. Sluit socket.
                    mainSocket.Close();
                }
            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show(ex.Message, "PacketSniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int intReceived = mainSocket.EndReceive(ar);

                // Analyseer ontvangen bytes.
                ParseData(byteData, intReceived);

                if (bGaDoorMetCapturen)
                {
                    byteData = new byte[4096];

                    // Nog een call naar BeginReceive om door te gaan met ontvangen van binnenkomende packets.
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show(ex.Message, "PacketSniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                TreeViewItem rootItem = new TreeViewItem();
                // Alle protocol packets zijn geëncapsuleerd in het IP datagram, we parsen dus de IP header om te zien welk protocol data zich hier bevindt.
                IPHeader ipHeader = new IPHeader(byteData, nReceived);
                TreeViewItem ipItem = MakeIPTreeViewItem(ipHeader);
                rootItem.Items.Add(ipItem);
                // Volgens het protocol dat meegedragen wordt door het IP datagram, parsen we het data field van het datagram.
                switch (ipHeader.ProtocolType)
                {
                    case Protocol.ICMP:
                        //IPHeader.Data bezit de data die gedragen wordt via het IP datagram, lengte van de header.
                        Debug.WriteLine("ICMP test");
                        // HIER MOET NOG HEEL WAT CODE
                        break;


                    case Protocol.TCP:
                        // IPHeader.Data bezit de data die gedragen wordt via het IP datagram, lengte van de header. 
                        TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                        TreeViewItem tcpItem = MakeTCPTreeViewItem(tcpHeader);
                        rootItem.Items.Add(tcpItem);
                        // Als de poort gelijk is aan 53, dan is het onderliggende protocol DNS.
                        // Note: DNS kan enkel TCP of UDP gebruiken, daarom --> 2 keer controle.
                        if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                        {
                            TreeViewItem dnsItem = MakeDNSTreeViewItem(tcpHeader.Data, tcpHeader.MessageLength);
                            rootItem.Items.Add(dnsItem);
                        }
                        break;

                    case Protocol.UDP:
                        // IPHeader.Data bezit de data die gedragen wordt via het IP datagram, lengte van de header. 
                        UDPHeader udpHeader = new UDPHeader(ipHeader.Data, ipHeader.MessageLength);
                        TreeViewItem udpItem = MakeUDPTreeViewItem(udpHeader);
                        rootItem.Items.Add(udpItem);
                        // Als de poort gelijk is aan 53, dan is het onderliggende protocol DNS.
                        // Note: DNS kan enkel TCP of UDP gebruiken, daarom --> 2 keer controle.
                        if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                        {
                            // Lengte van UDP header is altijd 8 bytes, dus we trekken deze af van totale lengte om eigenlijke lengte van de data te kennen.
                            TreeViewItem dnsItem = MakeDNSTreeViewItem(udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8);
                            rootItem.Items.Add(dnsItem);
                        }
                        break;

                    case Protocol.Unknown:
                        break;
                }
                AddTreeItem addTreeViewItem = new AddTreeItem(OnAddTreeViewItem);
                rootItem.Header = ipHeader.SourceAddress.ToString() + "-" + ipHeader.DestinationAddress.ToString(); //!!!!!!!!!!!!!!!!!
                                                                                                                    // Thread: veilig toevoegen van de Items.
                treeView.Dispatcher.Invoke(addTreeViewItem, new object[] { rootItem });
            }));
            }

        // Helper functie die informatie teruggeeft vanuit de IP header aan de tree node.
        private TreeViewItem MakeIPTreeViewItem(IPHeader ipHeader)
        {
            TreeViewItem ipItem = new TreeViewItem();
            ipItem.Header = "IP";
            ipItem.Items.Add("Ver: " + ipHeader.Version);
            ipItem.Items.Add("Header Length: " + ipHeader.HeaderLength);
            ipItem.Items.Add("Differntiated Services: " + ipHeader.DifferentiatedServices);
            ipItem.Items.Add("Total Length: " + ipHeader.TotalLength);
            ipItem.Items.Add("Identification: " + ipHeader.Identification);
            ipItem.Items.Add("Flags: " + ipHeader.Flags);
            ipItem.Items.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipItem.Items.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.ICMP:
                    ipItem.Items.Add("Protocol: " + "ICMP");
                    break;
                case Protocol.TCP:
                    ipItem.Items.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipItem.Items.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipItem.Items.Add("Protocol: " + "Unknown");
                    break;
            }
            ipItem.Items.Add("Checksum: " + ipHeader.Checksum);
            ipItem.Items.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipItem.Items.Add("Destination: " + ipHeader.DestinationAddress.ToString());
            return ipItem;
        }

        // Helper functie die informatie teruggeeft vanuit de TCP header aan de tree node.
        private TreeViewItem MakeTCPTreeViewItem(TCPHeader tcpHeader)
        {
            TreeViewItem tcpItem = new TreeViewItem();
            tcpItem.Header = "TCP";
            tcpItem.Items.Add("Source Port: " + tcpHeader.SourcePort);
            tcpItem.Items.Add("Destination Port: " + tcpHeader.DestinationPort);
            tcpItem.Items.Add("Sequence Number: " + tcpHeader.SequenceNumber);
            if (tcpHeader.AcknowledgementNumber != "")
                tcpItem.Items.Add("Acknowledgement Number: " + tcpHeader.AcknowledgementNumber);
            tcpItem.Items.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpItem.Items.Add("Flags: " + tcpHeader.Flags);
            tcpItem.Items.Add("Window Size: " + tcpHeader.WindowSize);
            tcpItem.Items.Add("Checksum: " + tcpHeader.Checksum);
            if (tcpHeader.UrgentPointer != "")
                tcpItem.Items.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);
            return tcpItem;
        }

        // Helper functie die informatie teruggeeft vanuit de UDP header aan de tree node.
        private TreeViewItem MakeUDPTreeViewItem(UDPHeader udpHeader)
        {
            TreeViewItem udpItem = new TreeViewItem();
            udpItem.Header = "UDP";
            udpItem.Items.Add("Source Port: " + udpHeader.SourcePort);
            udpItem.Items.Add("Destination Port: " + udpHeader.DestinationPort);
            udpItem.Items.Add("Length: " + udpHeader.Length);
            udpItem.Items.Add("Checksum: " + udpHeader.Checksum);
            return udpItem;
        }

        // Helper functie die informatie teruggeeft vanuit de DNS header aan de tree node.
        private TreeViewItem MakeDNSTreeViewItem(byte[] byteData, int nLength)
        {
            DNSHeader dnsHeader = new DNSHeader(byteData, nLength);
            TreeViewItem dnsItem = new TreeViewItem();
            dnsItem.Header = "DNS";
            dnsItem.Items.Add("Identification: " + dnsHeader.Identification);
            dnsItem.Items.Add("Flags: " + dnsHeader.Flags);
            dnsItem.Items.Add("Questions: " + dnsHeader.TotalQuestions);
            dnsItem.Items.Add("Answer RRs: " + dnsHeader.TotalAnswerRRs);
            dnsItem.Items.Add("Authority RRs: " + dnsHeader.TotalAuthorityRRs);
            dnsItem.Items.Add("Additional RRs: " + dnsHeader.TotalAdditionalRRs);
            return dnsItem;
        }

        private void OnAddTreeViewItem(TreeViewItem item)
        {
            treeView.Items.Add(item);
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            FullSizeButton.IsEnabled = false;
            GetInterfaces();
        }

        private void GetInterfaces()
        {
            // Haal lijst met interfaces af en koppel aan listbox.
            string strIP = null;
            IPHostEntry HostEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HostEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HostEntry.AddressList)
                {
                    strIP = ip.ToString();
                    lbInterfaces.Items.Add(strIP);
                }
            }
        }
        private void btnRefresh_Click(object sender, RoutedEventArgs e)
        {
            lbInterfaces.Items.Clear();
            GetInterfaces();
        }
        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            if (bGaDoorMetCapturen)
            {
                mainSocket.Close();
            }
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
    }
}

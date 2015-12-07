using eExNetworkLibrary;
using eExNetworkLibrary.IP;
using eExNetworkLibrary.Routing;
using eExNetworkLibrary.TCP;
using eExNetworkLibrary.Utilities;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;

namespace NetworkSniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        //Create a list for the interfaces
        List<EthernetInterface> wpcInterfaces = new List<EthernetInterface>();

        //Get all local interfaces
        WinPcapInterface[] arWpc = EthernetInterface.GetAllPcapInterfaces();

        //Create a router
        Router rRouter = new Router();
        public MainWindow()
        {
            InitializeComponent();
        }
        private void GetRouter()
        {

            //Foreach WinPcapInterface of this host
            foreach (WinPcapInterface wpc in arWpc)
            {
                if (wpc.Description == "Microsoft") //Tim added: only use my real adapter
                {
                    if (wpc.Addresses.Where(p => p.Address == new IPAddress(new byte[] { 0, 0, 0, 0 }).Address).Count() > 0) //Tim added: Only select interface that have at least one valid, non 0.0.0.0 ip address
                    {
                        //Create a new interface handler and start it
                        EthernetInterface ipInterface = new EthernetInterface(wpc);
                        ipInterface.Start();

                        //Then add it to the router and to our list
                        wpcInterfaces.Add(ipInterface);
                        rRouter.AddInterface(ipInterface);
                    }
                }
            }

            //Create a TCP frame
            TCPFrame tcpFrame = new TCPFrame();
            tcpFrame.DestinationPort = 80;
            tcpFrame.SourcePort = 12345;
            tcpFrame.AcknowledgementFlagSet = true;

            //Create an IP frame and put the TCP frame into it
            IPv4Frame ipFrame = new IPv4Frame();
            ipFrame.DestinationAddress = IPAddress.Parse("192.168.0.1");
            ipFrame.SourceAddress = IPAddress.Parse("192.168.1.254");

            ipFrame.EncapsulatedFrame = tcpFrame;

            rRouter.Start(); //Tim added:
                             //Send the frame
            rRouter.PushTraffic(tcpFrame);

            //Cleanup resources
            rRouter.Cleanup();

            //Start the cleanup process for all interfaces
            foreach (EthernetInterface ipInterface in wpcInterfaces)
            {
                ipInterface.Cleanup();
            }

            //Stop all handlers
            rRouter.Stop();

            //Stop all interfaces
            foreach (EthernetInterface ipInterface in wpcInterfaces)
            {
                ipInterface.Stop();
            }
        }
    }
}

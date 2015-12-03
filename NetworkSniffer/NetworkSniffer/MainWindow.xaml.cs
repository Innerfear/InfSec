using eExNetworkLibrary;
using System.Windows;

namespace NetworkSniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        MainHandler HandlerTemp = new MainHandler();
        InterfaceConnector IntConn = new InterfaceConnector();
        public MainWindow()
        {
            InitializeComponent();
        }
        
        private void StartMethod()
        {
            HandlerTemp.Start();
        }

        private void RandomMethod()
        {

        }
        
    }
}

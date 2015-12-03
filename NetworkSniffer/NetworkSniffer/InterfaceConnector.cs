using System;
using eExNetworkLibrary;
using eExNetworkLibrary.Utilities;

namespace NetworkSniffer
{
    class InterfaceConnector : TrafficHandler
    {
        WinPcapInterface[] arWpc = EthernetInterface.GetAllPcapInterfaces();

        public override void Cleanup()
        {
            throw new NotImplementedException();
        }

        // This method is called when the traffic handler is removed from 
        // a compilation and should stop down.
        // This method should in first place cleanup memory and stop threads, but
        // do no time-consuming recovery operations which involve the network.
        public override void Stop()
        {
            //Place stop stuff here.
            base.Stop(); //Don't forget to stop the engines
        }

        // This method is called when the traffic handler is inserted into a
        // network compilation and should start up
        public override void Start()
        {
            //Place start stuff here.
            base.Start(); //Don't forget to start the engines
        }

        protected override void HandleTraffic(Frame fInputFrame)
        {
            throw new NotImplementedException();
        }
    }
}

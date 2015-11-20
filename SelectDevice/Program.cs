using SharpPcap;
using SharpPcap.AirPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SelectDevice
{
    class Program
    {
        static void Main(string[] args)
        {
            //Print SharpPcap versie
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}, SelectDevice.Program.cs", ver);

            //Retrieve device list
            var devices = CaptureDeviceList.Instance;

            //No devices found print:
            if (devices.Count <1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            //print out devices
            foreach(var dev in devices)
            {
                //Description
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            var device = devices[i];

            //Register our handler function to the 'packet arrivel' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

            //Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            if (device is AirPcapDevice)
            {
                var airPcap = device as AirPcapDevice;
                airPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp, readTimeoutMilliseconds);
            }

            else if (device is WinPcapDevice)
            {
                var winPcap = device as WinPcapDevice;
                winPcap.Open(SharpPcap.WinPcap.OpenFlags.DataTransferUdp | SharpPcap.WinPcap.OpenFlags.NoCaptureLocal, readTimeoutMilliseconds);
            }

            else if (device is LibPcapLiveDevice)
            {
                var livePcapDevice = device as LibPcapLiveDevice;
                livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            }
            else
            {
                throw new System.InvalidOperationException("Unknown device type of " + device.GetType());
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...", device.Name, device.Description);

            //Start capturing process
            device.StartCapture();

            //Wait for 'enter' from user
            Console.ReadLine();

            //Stop capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            //Print out the device stats
            Console.WriteLine(device.Statistics.ToString());

            //close pcap device
            device.Close();
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);
            Console.WriteLine(e.Packet.ToString());
        }
    }
}

using SharpPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestingTutorials
{
    class Program
    {
        static void Main(string[] args)
        {
            //SharpPcap version
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap{0}, Example1.IfList.cs", ver );

            //Device list verkrijgen
            CaptureDeviceList devices = CaptureDeviceList.Instance;

            //Error bij geen devices
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine.");
                return;
            }

            Console.WriteLine("\nThe following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------\n");

            //Print gevonden network devices
            foreach(ICaptureDevice dev in devices)
                Console.WriteLine("{0}\n", dev.ToString());

            Console.WriteLine("Hit 'Enter' to exit to continue");
            Console.ReadLine();


            
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace PackageCollections
{
    public class Package
    {
        public volatile List<PackageHandle> array;
        private DllInvoke inv;
        private int dev = 0;
        private int package = 0;
        private string dllpath = AppDomain.CurrentDomain.BaseDirectory + "ZixpcapLib.dll";
        public Package(int dev)
        {
            this.dev = dev;
            array = new List<PackageHandle>();
            inv = new DllInvoke(dllpath);
            Task.Run(() => { SetArgs(); });
        }
        public Package(int dev, int package)
        {
            this.package = package;
            this.dev = dev;
            inv = new DllInvoke(dllpath);
            array = new List<PackageHandle>();
            Task.Run(() => { SetArgs(); });
        }
        public Package()
        {
            inv = new DllInvoke(dllpath);
        }
        public string[] GetDevices()
        {
            byte[] dev = new byte[4096];
            inv.Init_Device(ref dev[0]);
            return System.Text.Encoding.Default.GetString(dev).Trim().Split('\n');
        }
        public void SetArgs()
        {
            inv.Init_Args(dev);
            inv.Get_Args_Safe(package);
        }
        public void GetPacks(ref bool control)
        {
            while (control)
            {
                if (inv.Get_Length() > 0)
                {
                    PackageHandle ph = new PackageHandle();
                    ph.header = new pcap_pkthdr();
                    Thread.Sleep(30);
                    int len = inv.Get_Package_Length();
                    ph.pkt_data = new byte[len];
                    inv.Get_Package(ref ph.header, ref ph.pkt_data[0],  len);
                    array.Add(ph);
                }
            }
        }
        public int Get_Length()
        {
            return inv.Get_Length();
        }
        public void Reset()
        {
            inv.Reset();
        }
    }
}

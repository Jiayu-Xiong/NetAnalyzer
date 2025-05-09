using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PackageCollections
{
	class DllInvoke
	{
		[DllImport("kernel32.dll")]
		private extern static IntPtr LoadLibrary(string path);
		[DllImport("kernel32.dll")]
		private extern static IntPtr GetProcAddress(IntPtr lib, string funcName);
		[DllImport("kernel32.dll")]
		private extern static bool FreeLibrary(IntPtr lib);
		private IntPtr hLib;
		public DllInvoke(string DLLPath)
		{
			hLib = LoadLibrary(DLLPath);
		}
		~DllInvoke()
		{
			FreeLibrary(hLib);
		}
		public Delegate Invoke(string APIName, Type t)
		{
			IntPtr api = GetProcAddress(hLib, APIName);
			return (Delegate)Marshal.GetDelegateForFunctionPointer(api, t);
		}
		public void Init_Device(ref byte args)
		{
			init_device dev = (init_device)Invoke("init_device", typeof(init_device));
			dev(ref args);
		}
		public void Reset()
		{
			reset rst = (reset)Invoke("reset", typeof(reset));
			rst();
		}
		public int Get_Length()
		{
			get_length len = (get_length)Invoke("get_length", typeof(get_length));
			return len();
		}
		public void Get_Package(ref pcap_pkthdr pht, ref byte pkt_data, int len)
		{
			get_package pack = (get_package)Invoke("get_package", typeof(get_package));
			pack(ref pht, ref pkt_data, len);
		}
		public void Get_Args_Safe(int package)
		{
			get_args_safe arg = (get_args_safe)Invoke("get_args_safe", typeof(get_args_safe));
			arg(package);
		}
		public bool Init_Args(int dev)
		{
			init_args arg = (init_args)Invoke("init_args", typeof(init_args));
			return arg(dev);
		}
		public int Get_Package_Length()
		{
			get_package_length pack = (get_package_length)Invoke("get_package_length", typeof(get_package_length));
			return pack();
		}
		public delegate void init_device(ref byte args);
		public delegate void reset();
		public delegate int get_length();
		public delegate void get_package(ref pcap_pkthdr pht,ref byte pkt_data,  int len);
		public delegate void get_args_safe(int package);
		public delegate bool init_args(int dev);
		public delegate int get_package_length();
	}
}

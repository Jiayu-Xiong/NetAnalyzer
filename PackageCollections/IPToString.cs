using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PackageCollections
{
    public static class IPToString
    {
        public static string MacAddrToStringHex(byte[] args)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(args[0].ToString("X"));
            for (int circ = 1; circ < 6; circ++)
            {
                sb.Append(".");
                sb.Append(args[circ].ToString("X"));
            }
            return sb.ToString();
        }
        public static string MacAddrToString(byte[] args)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(args[0].ToString());
            for (int circ = 1; circ < 6; circ++)
            {
                sb.Append(".");
                sb.Append(args[circ].ToString());
            }
            return sb.ToString();
        }
        public static string IPV4AddrToString(byte[] args)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(args[0].ToString());
            for (int circ = 1; circ < 4; circ++)
            {
                sb.Append(".");
                sb.Append(args[circ].ToString());
            }
            return sb.ToString();
        }
        public static string IPV6AddrToString(ushort[] args)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(args[0].ToString());
            for (int circ = 1; circ < 8; circ++)
            {
                sb.Append(".");
                sb.Append(args[circ].ToString());
            }
            return sb.ToString();
        }
    }
}

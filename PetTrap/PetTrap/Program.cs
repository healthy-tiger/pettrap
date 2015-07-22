using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace PetTrap
{
    class Program
    {
        static void Main(string[] args)
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            s.Bind(new IPEndPoint(IPAddress.Loopback, 162));
            try
            {
                EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                byte[] buf = new byte[2048];
                int len = s.ReceiveFrom(buf, ref ep);

                SnmpTrap trap = SnmpTrap.ReadSnmpTrap(buf, 0);
                Console.WriteLine(trap);
            }
            finally
            {
                s.Shutdown(SocketShutdown.Both);
                s.Close();
            }
        }
    }
}

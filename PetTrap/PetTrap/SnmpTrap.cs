using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PetTrap
{
    public enum SnmpTag:byte
    {
        None = 0x00,
        Integer	= 0x02,
        OctetString = 0x04,
        ObjectId = 0x06,
        Sequence = 0x30,
        Structured = 0x20,
        SnmpNetworkAddress = 0x40,
        SnmpTimestamp = 0x43
    }

    public class SnmpTrap
    {
        public static void ReadTL(byte[] src, ref int offset, out SnmpTag tag, out int length) {
            tag = (SnmpTag)src[offset];
            offset++;

            int len = 0;
            if((src[offset] & 0x80) > 0) {
                int nl = src[offset] & 0x7f;
                offset++;
                for(int i = 0; i < nl; i++) {
                    len = (len << 8) + src[offset];
                    offset++;
                }
            }
            else {
                len = src[offset];
                offset++;
            }
            length = len;
        }

        public static byte[] ReadTLV(byte[] src, ref int offset, out SnmpTag tag)
        {
            int o = offset;
            SnmpTag t;
            int len;
            ReadTL(src, ref o, out t, out len);
            byte[] v = new byte[len];
            Buffer.BlockCopy(src, o, v, 0, len);
            tag = t;
            offset = o + len;
            return v;
        }

        public static int ParseInteger(byte[] src)
        {
            int v = 0;
            for (int i = 0; i < src.Length; i++)
            {
                v = (v << 8) + src[i];
            }
            return v;
        }

        public static int[] ParseObjectId(byte[] src)
        {
            List<int> ol = new List<int>();
            ol.Add((int)Math.Floor((double)src[0] / 40));
            ol.Add(src[0] % 40);
            int ip = 0;
            for (int i = 1; i < src.Length; i++)
            {
                int ti = (int)src[i];
                ip = (ip << 7) + (ti & 0x7f);
                if ((ti & 0x80) == 0)
                {
                    ol.Add(ip);
                    ip = 0;
                }
            }
            return ol.ToArray();
        }

        public static IPAddress ParseSnmpNetworkAddress(byte[] src)
        {
            return new IPAddress(src);
        }

        public static SnmpTrap ReadSnmpTrap(byte[] src, int offset)
        {
            SnmpTag tag;
            byte[] value = null;
            int o = offset;
            int len;

            ReadTL(src, ref o, out tag, out len);
            if (tag != SnmpTag.Sequence)
            {
                throw new FormatException("Invalid Trap structure");
            }

            int snmprev;
            value = ReadTLV(src, ref o, out tag);
            if (tag != SnmpTag.Integer)
            {
                throw new FormatException("No snmp revision");
            }
            snmprev = ParseInteger(value);
            if (snmprev != 0)
            {
                throw new FormatException("Unsupported SNMP Trap revision");
            }

            SnmpTrap trap = new SnmpTrap();

            string community;
            value = ReadTLV(src, ref o, out tag);
            if (tag != SnmpTag.OctetString)
            {
                throw new FormatException("No Community String");
            }
            community = Encoding.ASCII.GetString(value);

            ReadTL(src, ref o, out tag, out len);
            if ((tag & SnmpTag.Structured) == 0)
            {
                throw new FormatException("Invalid Trap structure");
            }

            value = ReadTLV(src, ref o, out tag);
            int[] enterprise = ParseObjectId(value);

            value = ReadTLV(src, ref o, out tag);
            if(tag != SnmpTag.SnmpNetworkAddress) {
                throw new FormatException("No Agent Address");
            }
            IPAddress agentaddr = ParseSnmpNetworkAddress(value);

            value = ReadTLV(src, ref o, out tag);
            if (tag != SnmpTag.Integer)
            {
                throw new FormatException("No Generic Trap");
            }
            int generictrap = ParseInteger(value);

            value = ReadTLV(src, ref o, out tag);
            if (tag != SnmpTag.Integer)
            {
                throw new FormatException("No Specific Trap");
            }
            int specifictrap = ParseInteger(value);

            value = ReadTLV(src, ref o, out tag);
            if (tag != SnmpTag.SnmpTimestamp)
            {
                throw new FormatException("No Timestamp");
            }
            int timestamp = ParseInteger(value);

            ReadTL(src, ref o, out tag, out len);
            if (tag != SnmpTag.Sequence)
            {
                throw new FormatException("No Variable Bindings");
            }

            trap.Enterprise = enterprise;
            trap.AgentAddr = agentaddr;
            trap.GenericTrap = generictrap;
            trap.SpecificTrap = specifictrap;
            trap.TimeStamp = timestamp;

            int end = o + len;
            while (o < end)
            {
                ReadTL(src, ref o, out tag, out len);
                if (tag != SnmpTag.Sequence)
                {
                    throw new FormatException("Unexpected Object");
                }

                value = ReadTLV(src, ref o, out tag);
                if (tag != SnmpTag.ObjectId)
                {
                    throw new FormatException("No Object Id");
                }
                int[] oid = ParseObjectId(value);
                value = ReadTLV(src, ref o, out tag);

                trap.VariableBindings.Add(new Tuple<int[], SnmpTag, byte[]>(oid, tag, value));
            }

            return trap;
        }

        public String Community { get; set; }
        public int[] Enterprise { get; set; }
        public IPAddress AgentAddr { get; set; }
        public int GenericTrap { get; set; }
        public int SpecificTrap { get; set; }
        public int TimeStamp { get; set; }
        public List<Tuple<int[], SnmpTag, byte[]>> VariableBindings;

        public SnmpTrap()
        {
            this.Community = null;
            this.Enterprise = null;
            this.AgentAddr = null;
            this.GenericTrap = 0;
            this.SpecificTrap = 0;
            this.TimeStamp = 0;
            this.VariableBindings = new List<Tuple<int[], SnmpTag, byte[]>>();
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Community: " + this.Community);
            sb.AppendLine("Enterprise: " + String.Join(".", this.Enterprise));
            sb.AppendLine("Agent Address: " + this.AgentAddr.ToString());
            sb.AppendLine("Generic Trap: " + this.GenericTrap);
            sb.AppendLine("Specific trap: " + this.SpecificTrap);
            sb.AppendLine("Time Stamp: " + this.TimeStamp);
            foreach (var t in this.VariableBindings)
            {
                sb.AppendLine(String.Join(".", t.Item1) + ", " + t.Item2 + ", " + String.Join(" ", t.Item3));
            }

            return sb.ToString();
        }
    }
}

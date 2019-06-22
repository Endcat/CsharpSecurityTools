using System;
using System.Runtime.InteropServices;
using System.Net;
using System.IO;
using System.Text;
using System.Net.Sockets;
using System.Net;

namespace CsharpSecurityTools
{
     class MainClass
     {
          [DllImport("user32", CharSet = CharSet.Auto)]
          static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

          [DllImport("libc")]
          static extern void printf(string message);
          static void GetParamFuzz(string[] args)
          {
               string url = args[0];
               int index = url.IndexOf("?");
               string[] parms = url.Remove(0, index + 1).Split('&');
               foreach (string parm in parms)
               {
                    //Console.WriteLine(parm);
                    string xssUrl = url.Replace(parm, parm + "fd<xss>sa"); // pollution
                    string sqlUrl = url.Replace(parm, parm + "fd'sa");

                    //Console.WriteLine(xssUrl);
                    //Console.WriteLine(sqlUrl);
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                    request.Method = "GET";

                    string sqlresp = string.Empty;
                    using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream())) // dispose optimize
                         sqlresp = rdr.ReadToEnd();

                    request = (HttpWebRequest)WebRequest.Create(xssUrl);
                    request.Method = "GET";
                    string xssresp = string.Empty;

                    using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                         xssresp = rdr.ReadToEnd();

                    if (xssresp.Contains("<xss>"))
                         Console.WriteLine("Possible XSS point found in parameter: " + parm);

                    if (sqlresp.Contains("error in your SQL syntax"))
                         Console.WriteLine("SQL injection point found in parameter: " + parm);

               }
          }

          static void PostParamFuzz(string[] args)
          {
               // get post request from burp
               string[] requestLines = File.ReadAllLines(args[0]);
               string[] parms = requestLines[requestLines.Length - 1].Split('&');
               string host = string.Empty;
               StringBuilder requestBuilder = new StringBuilder();

               foreach (string ln in requestLines)
               {
                    if (ln.StartsWith("Host:"))
                         host = ln.Split(' ')[1].Replace("\r", string.Empty); // delete \r in mono
                    requestBuilder.Append(ln + "\n");
               }

               string request = requestBuilder.ToString() + "\r\n";
               // request should be end with \r\n
               //Console.WriteLine(request);
               IPEndPoint rhost = new IPEndPoint(IPAddress.Parse(host), 80);
               foreach (string parm in parms)
               {
                    using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                         sock.Connect(rhost);

                         string val = parm.Split('=')[1];
                         string req = request.Replace("=" + val, "=" + val + "'"); // pollution

                         byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                         sock.Send(reqBytes);

                         byte[] buf = new byte[sock.ReceiveBufferSize];

                         sock.Receive(buf);
                         string response = Encoding.ASCII.GetString(buf);
                         if (response.Contains("error in yout SQL syntax"))
                         {
                              Console.WriteLine("Parameter "+parm+" seems vulunable");
                              Console.Write(" to SQL injection with value: " + val + "'");
                         }
                    }
               }
               
          }

          static void Main(string[] args)
          {
               // use cmd params to replace arguments string array
               OperatingSystem os = Environment.OSVersion;
               if (os.Platform == PlatformID.Win32NT)
               {
                    MessageBox(IntPtr.Zero, "Hello!", "Hello", 0);
               }
               else
               {
                    printf("Hello Miao!");
               }
               //Console.WriteLine("Hello World!");

               //GetParamFuzz part start
               string[] arguments = new string[9];
               arguments[0] = "http://192.168.241.128/cgi-bin/badstore.cgi?searchquery=hello&action=search&x=0&y=0";
               GetParamFuzz(arguments);
               //GetParamFuzz part end

          }


     }
}


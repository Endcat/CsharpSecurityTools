using System;
using System.Net.Security;
using System.Net;
using System.Xml.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace OpenVASAutomatic
{
     class Program
     {
          static void Main1(string[] args)
          {
               // Get OpenVAS Version
               using (OpenVASSession session = new OpenVASSession("admin","admin","192.168.1.xxx"))
               {
                    XDocument doc = session.ExecuteCommand(
                         XDocument.Parse("<get_version />"));

                    Console.WriteLine(doc.ToString());
               }
          }

          static void Main2(string[] args)
          {
               using (OpenVASSession session = new OpenVASSession("admin","admin","192.168.1.xxx"))
               {
                    using (OpenVASManager manager = new OpenVASManager(session))

                    {
                         XDocument version = manager.GetVersion();
                         Console.WriteLine(version);

                         
                    }
               }
          }

          static void Main3(string[] args)
          {
               
          }

     }

     public class OpenVASSession : IDisposable
     {
          private SslStream _stream = null;

          public OpenVASSession(string user, string pass, string host, int port = 9390)
          {
               this.ServerIPAddress = IPAddress.Parse(host);
               this.ServerPort = port;
               this.Authenticate(user, pass);
          }

          public string Username { get; set; }
          public string Password { get; set; }
          public IPAddress ServerIPAddress { get; set; }
          public int ServerPort { get; set; }

          public SslStream Stream
          {
               get
               {
                    if (_stream == null)
                         GetStream();

                    return _stream;
               }

               set { _stream = value; }
          }

          public XDocument Authenticate(string username, string password)
          {
               XDocument authXML = new XDocument(
                    new XElement("authenticate",
                         new XElement("credentials",
                              new XElement("username", username),
                              new XElement("password", password))));

               XDocument response = this.ExecuteCommand(authXML);

               if (response.Root.Attribute("status").Value != "200")
                    throw new Exception("Authentication Failed");

               this.Username = username;
               this.Password = password;

               return response;
          }

          public XDocument ExecuteCommand(XDocument doc)
          {
               ASCIIEncoding enc = new ASCIIEncoding();

               string xml = doc.ToString();
               this.Stream.Write(enc.GetBytes(xml), 0, xml.Length);

               return ReadMessage(this.Stream);
          }

          private XDocument ReadMessage(SslStream sslStream)
          {
               using (var stream = new MemoryStream())
               {
                    int bytesRead = 0;
                    do
                    {
                         byte[] buffer = new byte[2048];
                         bytesRead = sslStream.Read(buffer, 0, buffer.Length);
                         stream.Write(buffer, 0, bytesRead);
                         if (bytesRead < buffer.Length)
                         {
                              try
                              {
                                   string xml = System.Text.Encoding.ASCII.GetString(stream.ToArray());
                                   return XDocument.Parse(xml);
                              }
                              catch
                              {
                                   continue;
                              }
                         }
                    }
                    while (bytesRead > 0);
               }
               return null;
          }

          private void GetStream()
          {
               if (_stream == null || !_stream.CanRead)
               {
                    TcpClient client = new TcpClient(this.ServerIPAddress.ToString(), this.ServerPort);

                    _stream = new SslStream(client.GetStream(), false,
                         new RemoteCertificateValidationCallback(ValidateServerCertificate),
                         (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => null);

                    _stream.AuthenticateAsClient("OpenVAS", null, SslProtocols.Tls, false);
               }
          }

          private bool ValidateServerCertificate(object sender, X509Certificate certificate,X509Chain chain, SslPolicyErrors sslPolicyErrors)
          {
               return true;
          }

          public void Dispose()
          {
               if (_stream != null)
                    _stream.Dispose();
          }
               
     }

     public class OpenVASManager : IDisposable
     {
          private OpenVASSession _session;
          public OpenVASManager(OpenVASSession session)
          {
               if (session != null)
                    _session = session;
               else
                    throw new ArgumentNullException("session");
          }

          public XDocument GetVersion()
          {
               return _session.ExecuteCommand(XDocument.Parse("<get_version />"));
          }

          public XDocument GetScanConfigurations()
          {
               return _session.ExecuteCommand(XDocument.Parse("<get_configs />"));
          }

          public XDocument CreateSimpleTarget(string cidrRange, string targetName)
          {
               XDocument createTargetXML = new XDocument(
                    new XElement("create_target",
                         new XElement("name", targetName),
                         new XElement("hosts", cidrRange)));
               return _session.ExecuteCommand(createTargetXML);
          }

          //*** create_target
          //     <create_target>
          //          <name>Home Network</name>
          //          <hosts>192.168.1.xxx</hosts>
          //     <create_target>

          public XDocument CreateSimpleTask(string name, string comment, Guid configID, Guid targetID)
          {
               XDocument createTaskXML = new XDocument(
                    new XElement("create_task",
                         new XElement("name", name),
                         new XElement("comment", comment),
                         new XElement("config",
                              new XAttribute("id", configID.ToString()))),
                              new XElement("target",
                                   new XAttribute("id", targetID.ToString())));

               return _session.ExecuteCommand(createTaskXML);
          }

          public XDocument StartTask(Guid taskID)
          {
               XDocument startTaskXML = new XDocument(
                    new XElement("start_task",
                         new XAttribute("task_id", taskID.ToString())));

               return _session.ExecuteCommand(startTaskXML);
          }

          public XDocument GetTasks(Guid? taskID = null)
          {
               if (taskID != null)
                    return _session.ExecuteCommand(new XDocument(
                         new XElement("get_tasks",
                              new XAttribute("task_id", taskID.ToString()))));

               return _session.ExecuteCommand(XDocument.Parse("<get_tasks />"));
          }

          public XDocument GetTaskResults(Guid taskID)
          {
               XDocument getTaskResultsXML = new XDocument(
                    new XElement("get_results",
                         new XAttribute("task_id", taskID.ToString())));

               return _session.ExecuteCommand(getTaskResultsXML);
          }

          public void Dispose()
          {
               _session.Dispose();
          }
     }

}

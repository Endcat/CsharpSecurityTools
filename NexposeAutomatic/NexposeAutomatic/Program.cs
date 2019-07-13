using System;
using System.Net;
using System.Xml.Linq;
using System.Text;
using System.IO;
using System.Xml.XPath;
using System.Threading;

// References in Nexpose API
// Replacement of IPs needed

namespace NexposeAutomatic
{
     class Program
     {
          static void Main(string[] args)
          {
               using (NexposeSession session = new NexposeSession("admin","admin","192.168.2.171"))
               {
                    Console.WriteLine(session.sessionID);
               }
          }

          static void OtherMain(string[] args)
          {
               using (NexposeSession session = new NexposeSession("admin","password","192.168.2.171"))
               {
                    using (NexposeManager manager = new NexposeManager(session))
                    {
                         Console.WriteLine(manager.GetSystemInformation().ToString());
                    }
               }
          }

          static void FinalMain(string[] args)
          {
               using (NexposeSession session = new NexposeSession("admin","password","xxx.xxx.xxx.xxx"))
               {
                    using (NexposeManager manager = new NexposeManager(session))
                    {
                         string[][] ips =
                         {
                              new string[] { "192.168.2.169", string.Empty}
                         };

                         XDocument site = manager.CreateOrUpdateSite(Guid.NewGuid().ToString(), null, ips);

                         int siteID = int.Parse(site.Root.Attribute("site-id").Value);

                         XDocument scan = manager.ScanSite(siteID);
                         XElement ele = scan.XPathSelectElement("//SiteScanResponse/Scan");

                         int scanID = int.Parse(ele.Attribute("scan-id").Value);
                         XDocument status = manager.GetScanStatus(scanID);

                         while (status.Root.Attribute("status").Value != "finished")
                         {
                              Thread.Sleep(1000);
                              status = manager.GetScanStatus(scanID);
                              Console.WriteLine(DateTime.Now.ToLongDateString()+":"+status.ToString());
                         }

                         // Generate pdf report and delete site

                         byte[] report = manager.GetPdfSiteReport(siteID);
                         string outdir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                         string outpath = Path.Combine(outdir, siteID + ".pdf");
                         File.WriteAllBytes(outpath, report);

                         manager.DeleteSite(siteID);
                    }
               }
          }
     }

     public class NexposeManager : IDisposable
     {
          private readonly NexposeSession _session;
          public NexposeManager(NexposeSession session)
          {
               if (!session.IsAuthenticated)
                    throw new ArgumentException("Trying to create manager from " + "unauthenticared session. Please authenticate." + "session");

               _session = session;
          }

          public XDocument GetSystemInformation()
          {
               XDocument xml = new XDocument(new XElement("SystemInformationRequest", new XAttribute("session-id", _session.sessionID)));

               return (XDocument)_session.ExecuteCommand(xml);
          }


          public byte[] GetPdfSiteReport(int siteID)
          {
               XDocument doc = new XDocument(new XElement("ReportAdhocGenerateRequest",
                    new XAttribute("session-id", _session.sessionID),
                    new XElement("AdhocReportConfig",
                         new XAttribute("template-id", "audit-report"),
                         new XAttribute("format", "pdf"),
                         new XElement("Filters",
                              new XElement("filter",
                                   new XAttribute("type", "site"),
                                   new XAttribute("id", siteID))))));

               return (byte[])_session.ExecuteCommand(doc);
          }

          public XDocument DeleteSite(int siteID)
          {
               XDocument xml = new XDocument(
                    new XElement("SiteSDeleteRequest",
                         new XAttribute("session-id", _session.sessionID),
                         new XAttribute("site-id", siteID)));
               return (XDocument)_session.ExecuteCommand(xml);
          }

          public XDocument CreateOrUpdateSite(string name, string[] hostnames = null, string[][] ips = null, int siteID = -1)
          {
               XElement hosts = new XElement("Hosts");
               if (hostnames != null)
               {
                    foreach (string host in hostnames)
                         hosts.Add(new XElement("host", host));
               }

               if (ips != null)
               {
                    foreach (string[] range in ips)
                    {
                         hosts.Add(new XElement("range",
                              new XAttribute("from", range[0]),
                              new XAttribute("to", range[1])));
                    }
               }

               XDocument xml = new XDocument(
                    new XElement("SiteSaveRequest",
                         new XAttribute("session-id", _session.sessionID),
                         new XElement("Site",
                              new XAttribute("id", siteID),
                              new XAttribute("name", name),
                              hosts,
                              new XElement("ScanConfig",
                                   new XAttribute("name", "Full audit"),
                                   new XAttribute("templateID", "full-audit")))));

               return (XDocument)_session.ExecuteCommand(xml);
          }

          public XDocument ScanSite(int siteID)
          {
               XDocument xml = new XDocument(
                    new XElement("SiteScanRequest",
                         new XAttribute("session-id", _session.sessionID),
                         new XAttribute("site-id", siteID)));

               return (XDocument)_session.ExecuteCommand(xml);
          }

          public XDocument GetScanStatus(int scanID)
          {
               XDocument xml = new XDocument(
                    new XElement("ScanStatusRequest",
                         new XAttribute("session-id", _session.sessionID),
                         new XAttribute("scan-id", scanID)));

               return (XDocument)_session.ExecuteCommand(xml);
          }

          public void Dispose()
          {
               _session.Logout();
          }
     }

     public class NexposeSession : IDisposable
     {
          public NexposeSession(string username, string password, string host, int port = 3780, NexposeAPIVersion version = NexposeAPIVersion.v11)
          {
               this.Host = host;
               this.Port = port;
               this.APIVersion = version;

               ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, ssl) => true;

               this.Authenticate(username, password);
          }

          public string Host { get; set; }
          public int Port { get; set; }
          public bool IsAuthenticated { get; set; }
          public string sessionID { get; set; }
          public NexposeAPIVersion APIVersion { get; set; }

          public XDocument Authenticate(string username, string password)
          {
               XDocument cmd = new XDocument(new XElement("LoginRequest", new XAttribute("user-id", username), new XAttribute("password", password)));

               XDocument doc = (XDocument)this.ExecuteCommand(cmd);

               if (doc.Root.Attribute("success").Value == "1")
               {
                    this.sessionID = doc.Root.Attribute("session-id").Value;
                    this.IsAuthenticated = true;
               }
               else
                    throw new Exception("Authentication failed");

               return doc;
          }

          public object ExecuteCommand(XDocument commandXml)
          {
               string uri = string.Empty;
               switch (this.APIVersion)
               {
                    case NexposeAPIVersion.v11:
                         uri = "/api/1.1/xml";
                         break;
                    case NexposeAPIVersion.v12:
                         uri = "/api/1.2/xml";
                         break;
                    default:
                         throw new Exception("Unknown API Version.");
               }

               byte[] byteArray = Encoding.ASCII.GetBytes(commandXml.ToString());
               HttpWebRequest request = WebRequest.Create("https://" + this.Host + ":" + this.Port.ToString() + uri) as HttpWebRequest;
               request.Method = "POST";
               request.ContentType = "text/xml";
               request.ContentLength = byteArray.Length;
               using (Stream dataStream = request.GetRequestStream())
                    dataStream.Write(byteArray, 0, byteArray.Length);

               string response = string.Empty;
               using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
               {
                    using (StreamReader reader = new StreamReader(r.GetResponseStream()))
                         response = reader.ReadToEnd();

                    if (r.ContentType.Contains("multipart/mixed"))
                    {
                         string[] splitResponse = response.Split(new string[] { "--AxB9sl3299asdjvbA" }, StringSplitOptions.None);
                         splitResponse = splitResponse[2].Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);

                         string base64Data = splitResponse[1];
                         return Convert.FromBase64String(base64Data);
                    }
               }
               return XDocument.Parse(response);
          }

          public XDocument Logout()
          {
               XDocument cmd = new XDocument(new XElement("LogoutRequest",new XAttribute("session-id",this.sessionID)));

               XDocument doc = (XDocument)this.ExecuteCommand(cmd);
               this.IsAuthenticated = false;
               this.sessionID = string.Empty;

               return doc;

          }

          public void Dispose()
          {
               if (this.IsAuthenticated)
                    this.Logout();
          }
          
     }
     public enum NexposeAPIVersion
     {
          v11,
          v12
     };

}

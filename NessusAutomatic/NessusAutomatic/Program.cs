using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Threading;


// References for Nessus API

namespace NessusAutomatic
{
     class Program
     {
          // Main1 for NessusSession Class Testing
          public static void Main1(string[] args)
          {
               using (NessusSession session = new NessusSession("192.168.1.14", "admin", "password"))
               {
                    Console.WriteLine("Your authentication token is: " + session.Token);
               }
          }


          // Starting Nessus Scanning
          public static void Main(string[] args)
          {
               ServicePointManager.ServerCertificateValidationCallback = (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true;

               using (NessusSession session = new NessusSession("192.168.1.14", "admin", "password"))
               {
                    using (NessusManager manager = new NessusManager(session))
                    {
                         JObject policies = manager.GetScanPolicies();
                         string discoveryPolicyID = string.Empty;
                         foreach (JObject template in policies["templates"])
                         {
                              if (template["name"].Value<string>() == "basic")
                                   discoveryPolicyID = template["uuid"].Value<string>();
                         }

                         JObject scan = manager.CreateScan(discoveryPolicyID, "192.168.1.31", "Network Scan", "A simple scan of a simple IP address.");
                         int scanID = scan["scan"]["id"].Value<int>();
                         manager.StartScan(scanID);
                         JObject scanStatus = manager.GetScan(scanID);

                         while (scanStatus["info"]["status"].Value<string>() != "completed")
                         {
                              Console.WriteLine("Scan status: " + scanStatus["info"]["status"].Value<string>());
                              Thread.Sleep(5000);
                              scanStatus = manager.GetScan(scanID);
                         }

                         foreach (JObject vuln in scanStatus["vulnerabilities"])
                              Console.WriteLine(vuln.ToString());
                    }
               }
          }

     }

     public class NessusSession : IDisposable
     {
          public NessusSession(string host, string username, string password)
          {
               ServicePointManager.ServerCertificateValidationCallback = (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true;

               this.Host = host;
               if (!Authenticate(username, password))
                    throw new Exception("Authentication Failed");

          }

          public bool Authenticate(string username, string password)
          {
               JObject obj = new JObject();
               obj["username"] = username;
               obj["password"] = password;

               JObject ret = MakeRequest(WebRequestMethods.Http.Post, "/session", obj);

               if (ret["token"] == null)
                    return false;

               this.Token = ret["token"].Value<string>();
               this.Authenticated = true;

               return true;
          }

          public JObject MakeRequest(string method, string uri, JObject data = null, string token = null)
          {
               string url = "https://" + this.Host + ":8834" + uri;
               HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
               request.Method = method;

               if (!string.IsNullOrEmpty(token))
                    request.Headers["X-Cookie"] = "token=" + token;

               request.ContentType = "application/json";

               if (data != null)
               {
                    byte[] bytes = System.Text.Encoding.ASCII.GetBytes(data.ToString());
                    request.ContentLength = bytes.Length;
                    using (Stream requestStream = request.GetRequestStream())
                         requestStream.Write(bytes, 0, bytes.Length);
               }
               else
                    request.ContentLength = 0;

               string response = string.Empty;
               try
               {
                    using (StreamReader reader = new StreamReader(request.GetResponse().GetResponseStream()))
                         response = reader.ReadToEnd();
               }
               catch
               {
                    return new JObject();
               }

               if (string.IsNullOrEmpty(response))
                    return new JObject();
               return JObject.Parse(response);
          }


          public void LogOut()
          {
               if (this.Authenticated)
               {
                    MakeRequest("DELETE", "/session", null, this.Token);
                    this.Authenticated = false;
               }
          }

          public void Dispose()
          {
               if (this.Authenticated)
                    this.LogOut();
          }
          public string Host { get; set; }
          public bool Authenticated { get; set; }
          public string Token { get; set; }
     }
     public class NessusManager : IDisposable
     {
          NessusSession _session;
          public NessusManager(NessusSession session)
          {
               _session = session;
          }

          public JObject GetScanPolicies()
          {
               return _session.MakeRequest("GET", "/editor/policy/templates", null, _session.Token);
          }

          public JObject CreateScan(string policyID, string cidr, string name, string description)
          {
               JObject data = new JObject();
               data["uuid"] = policyID;
               data["settings"] = new JObject();
               data["settings"]["name"] = name;
               data["settings"]["text_targets"] = cidr;
               data["settings"]["description"] = description;

               return _session.MakeRequest("POST", "/scans", data, _session.Token);
          }

          public JObject StartScan(int scanID)
          {
               return _session.MakeRequest("POST", "/scans/" + scanID + "/launch", null, _session.Token);
          }

          public JObject GetScan(int scanID)
          {
               return _session.MakeRequest("GET", "/scans/" + scanID, null, _session.Token);
          }

          public void Dispose()
          {
               if (_session.Authenticated)
                    _session.LogOut();
               _session = null;
          }
     }

}
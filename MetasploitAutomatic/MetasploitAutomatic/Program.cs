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
     }

}

using System;
using System.Net;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace SqlmapAutomatic
{
     class Program
     {
          static void SqlmapScanner(string[] args)
          {
               using (SqlmapSession session = new SqlmapSession("127.0.0.1",8775))
               {
                    using (SqlmapManager manager = new SqlmapManager(session))
                    {
                         string taskid = manager.NewTask();

                         Dictionary<string, object> options = manager.GetOptions(taskid);
                         options["url"] = args[0];
                         options["flushsession"] = true;

                         manager.StartTask(taskid, options);

                         SqlmapStatus status = manager.GetScanStatus(taskid);
                         while (status.Status != "terminated")
                         {
                              System.Threading.Thread.Sleep(new TimeSpan(0, 0, 10));
                              status = manager.GetScanStatus(taskid);
                         }

                         List<SqlmapLogItem> logItems = manager.GetLog(taskid);
                         foreach (SqlmapLogItem item in logItems)
                              Console.WriteLine(item.Message);

                         manager.DeleteTask(taskid);
                    }
               }
          }
          static void Main(string[] args)
          {
               // Testing Session Class
               //string host = args[0];
               //int port = int.Parse(args[1]);
               //using (SqlmapSession session = new SqlmapSession(host,port))
               //{
               //     string response = session.ExecuteGet("/task/new");
               //     JToken token = JObject.Parse(response);
               //     string taskID = token.SelectToken("taskID").ToString();

               //     Console.WriteLine("New Task id: "+taskID);
               //     Console.WriteLine("Deleting task: "+taskID);

               //     response = session.ExecuteGet("/task/" + taskID + "/delete");
               //     token = JObject.Parse(response);
               //     bool success = (bool)token.SelectToken("success");

               //     Console.WriteLine("Delete successful: "+success);
               //}

               // Testing Manager Class
               //string host = args[0];
               //int port = int.Parse(args[1]);
               //using (SqlmapManager mgr = new SqlmapManager(new SqlmapSession(host,port)))
               //{
               //     string taskID = mgr.NewTask();

               //     Console.WriteLine("Created Task: " + taskID);
               //     Console.WriteLine("Deleting Task");
               //     bool success = mgr.DeleteTask(taskID);

               //     Console.WriteLine("Delete successful: "+success);

               //} // automatically clean and dispose manager

          }
     }

     public class SqlmapSession : IDisposable
     {
          private string _host = string.Empty;
          private int _port = 8775; // default port

          public SqlmapSession(string host, int port = 8775)
          {
               _host = host;
               _port = port;
          }

          public string ExecuteGet(string url)
          {
               HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://" + _host + ":" + _port + url);
               req.Method = "GET";

               string resp = string.Empty;
               using (StreamReader rdr = new StreamReader(req.GetResponse().GetResponseStream()))
                    resp = rdr.ReadToEnd();

               return resp;
          }

          public string ExecutePost(string url, string data)
          {
               byte[] buffer = Encoding.ASCII.GetBytes(data);
               HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://" + _host + ":" + _port + url);
               req.Method = "POST";
               req.ContentType = "application/json";
               req.ContentLength = buffer.Length;

               using (Stream stream = req.GetRequestStream())
               {
                    stream.Write(buffer, 0, buffer.Length);

                    string resp = string.Empty;
                    using (StreamReader r = new StreamReader(req.GetResponse().GetResponseStream()))
                         resp = r.ReadToEnd();

                    return resp;
               }
          }

          public void Dispose()
          {
               _host = null;
          }
     }

     public class SqlmapManager : IDisposable
     {
          private SqlmapSession _session = null;

          public SqlmapManager(SqlmapSession session)
          {
               if (session == null)
                    throw new ArgumentException("session");
               _session = session;
          }

          public string NewTask()
          {
               JToken tok = JObject.Parse(_session.ExecuteGet("/task/new"));
               return tok.SelectToken("taskid").ToString();
          }

          public bool DeleteTask(string taskid)
          {
               JToken tok = JObject.Parse(_session.ExecuteGet("/task/" + taskid + "/delete"));
               return (bool)tok.SelectToken("success");
          }

          public Dictionary<string, object> GetOptions(string taskid)
          {
               Dictionary<string, object> options = new Dictionary<string, object>();

               JObject tok = JObject.Parse(_session.ExecuteGet("/option/" + taskid + "/list"));

               tok = tok["options"] as JObject;

               foreach (var pair in tok)
                    options.Add(pair.Key, pair.Value);

               return options;
          }

          public bool StartTask(string taskID, Dictionary<string, object> opts)
          {
               string json = JsonConvert.SerializeObject(opts);
               JToken tok = JObject.Parse(_session.ExecutePost("/scan/" + taskID + "/start", json));
               return (bool)tok.SelectToken("success");
          }

          public SqlmapStatus GetScanStatus(string taskid)
          {
               JObject tok = JObject.Parse(_session.ExecuteGet("/scan/" + taskid + "/status"));

               SqlmapStatus stat = new SqlmapStatus();
               stat.Status = (string)tok["status"];

               if (tok["returncode"].Type != JTokenType.Null)
                    stat.ReturnCode = (int)tok["returncode"];

               return stat;
          }

          public List<SqlmapLogItem> GetLog(string taskid)
          {
               JObject tok = JObject.Parse(_session.ExecuteGet("/scan/" + taskid + "/log"));
               JArray items = tok["log"] as JArray;
               List<SqlmapLogItem> logItems = new List<SqlmapLogItem>();

               foreach (var item in items)
               {
                    SqlmapLogItem i = new SqlmapLogItem();
                    i.Message = (string)item["message"];
                    i.Level = (string)item["level"];
                    i.Time = (string)item["time"];
                    logItems.Add(i);
               }

               return logItems;
          }

          public void Dispose()
          {
               _session.Dispose();
               _session = null;
          }
     }

     public class SqlmapStatus
     {
          public string Status { get; set; }
          public int ReturnCode { get; set; }
     }

     public class SqlmapLogItem
     {
          public string Message { get; set; }
          public string Level { get; set; }
          public string Time { get; set; }
     }

}

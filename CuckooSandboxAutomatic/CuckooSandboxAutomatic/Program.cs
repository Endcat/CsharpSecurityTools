using System;
using Newtonsoft.Json.Linq;
using System.Net;
using System.IO;
using System.Collections.Generic;
using System.Collections;

namespace CuckooSandboxAutomatic
{
     class Program
     {
          static void Main(string[] args)
          {
               //CuckooSession session = new CuckooSession("127.0.0.1", 8090);
               //JObject response = session.ExecuteCommand("/cuckoo/status", "GET");
               //Console.WriteLine(response.ToString());

               CuckooSession session = new CuckooSession("127.0.0.1", 8090);
               using (CuckooManager manager = new CuckooManager(session))
               {
                    FileTask task = new FileTask();
                    task.Filepath = "/var/www/payload.exe";

                    int taskID = manager.CreateTask(task);
                    Console.WriteLine("Created task: " + task.ID);

                    task = (FileTask)manager.GetTaskDetails(taskID);
                    while (task.Status == "pending" || task.Status == "running")
                    {
                         Console.WriteLine("Waiting 30 seconds..."+task.Status);
                         System.Threading.Thread.Sleep(30000);
                         task = (FileTask)manager.GetTaskDetails(taskID);
                    }

                    if (task.Status == "failure")
                    {
                         Console.Error.WriteLine("There was an error:");
                         foreach (var error in task.Errors)
                              Console.Error.WriteLine(error);

                         return;
                    }

                    string report = manager.GetTaskReport(taskID).ToString();
                    Console.WriteLine(report);
               }
          }
     }

     public class CuckooSession
     {
          public CuckooSession(string host, int port)
          {
               this.Host = host;
               this.Port = port;
          }

          public JObject ExecuteCommand(string uri, string method)
          {
               HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://" + this.Host + ":" + this.Port + uri);
               req.Method = method;
               string resp = string.Empty;
               using (Stream str = req.GetResponse().GetResponseStream())
               using (StreamReader rdr = new StreamReader(str))
                    resp = rdr.ReadToEnd();

               JObject obj = JObject.Parse(resp);
               return obj;
          }

          public JObject ExecuteCommand(string uri, string method, IDictionary<string, object> parms)
          {
               HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://" + this.Host + ":" + this.Port + uri);
               req.Method = method;
               string boundary = String.Format("----------{0:N}", Guid.NewGuid());
               byte[] data = GetMultipartFormData(parms, boundary);

               req.ContentLength = data.Length;
               req.ContentType = "multipart/form-data; boundary=" + boundary;

               using (Stream parmStream = req.GetRequestStream())
                    parmStream.Write(data, 0, data.Length);

               string resp = string.Empty;
               using (Stream str = req.GetResponse().GetResponseStream())
               using (StreamReader rdr = new StreamReader(str))
                    resp = rdr.ReadToEnd();

               JObject obj = JObject.Parse(resp);
               return obj;
          }

          private byte[] GetMultipartFormData(IDictionary<string,object> postParameters, string boundary)
          {
               System.Text.Encoding encoding = System.Text.Encoding.ASCII;
               Stream formDataStream = new System.IO.MemoryStream();
               bool needsCLRF = false;

               foreach (var param in postParameters)
               {
                    if (needsCLRF)
                         formDataStream.Write(encoding.GetBytes("\r\n"), 0, encoding.GetByteCount("\r\n"));

                    needsCLRF = true;
                    if (param.Value is FileParameter)
                    {
                         FileParameter fileToUpload = (FileParameter)param.Value;
                         string header = string.Format("--{0}\r\nContent-Disposition: form-data; name=\"{1}\";" + "filename=\"{2}\";\r\nContent-Type: {3}\r\n\r\n", boundary, param.Key, fileToUpload.FileName ?? param.Key, fileToUpload.ContentType ?? "application/octet-stream");

                         formDataStream.Write(encoding.GetBytes(header), 0, encoding.GetByteCount(header));
                         formDataStream.Write(fileToUpload.File, 0, fileToUpload.File.Length);
                    }
                    else
                    {
                         string postData = string.Format("--{0}\r\nContent-Disposition: form-data;" + "name=\"{1}\"\r\n\r\n{2}", boundary, param.Key, param.Value);

                         formDataStream.Write(encoding.GetBytes(postData), 0, encoding.GetByteCount(postData));
                    }
               }

               string footer = "\r\n--" + boundary + "--\r\n";
               formDataStream.Write(encoding.GetBytes(footer), 0, encoding.GetByteCount(footer));

               formDataStream.Position = 0;
               byte[] formData = new byte[formDataStream.Length];
               formDataStream.Read(formData, 0, formData.Length);
               formDataStream.Close();

               return formData;
          }

          public string Host { get; set; }
          public int Port { get; set; }
     }

     public class CuckooManager : IDisposable
     {
          CuckooSession _session = null;
          public CuckooManager(CuckooSession session)
          {
               _session = session;
          }

          public int CreateTask(Task task)
          {
               string param = null, uri = "/tasks/create/";
               object val = null;

               if (task is FileTask)
               {
                    byte[] data;
                    using (FileStream str = new FileStream((task as FileTask).Filepath,FileMode.Open,FileAccess.Read))
                    {
                         data = new byte[str.Length];
                         str.Read(data, 0, data.Length);
                    }

                    param = "file";
                    uri += param;
                    val = new FileParameter(data, (task as FileTask).Filepath, "application/binary");
               }

               IDictionary<string, object> parms = new Dictionary<string, object>();
               parms.Add(param, val);
               parms.Add("package", task.Package);
               parms.Add("timeout", task.Timeout.ToString());
               parms.Add("options", task.Options);
               parms.Add("machine", task.Machine);
               parms.Add("platform", task.Platform);
               parms.Add("custom", task.Custom);
               parms.Add("memory", task.EnableMemoryDump.ToString());
               parms.Add("enforce_timeout", task.EnableEnforceTimeout.ToString());

               JObject resp = _session.ExecuteCommand(uri, "POST", parms);

               return (int)resp["task_id"];
          }

          public Task GetTaskDetails(int id)
          {
               string uri = "/task/view/" + id;
               JObject resp = _session.ExecuteCommand(uri, "GET");
               return TaskFactory.CreateTask(resp["task"]);
          }

          public JObject GetTaskReport(int id)
          {
               return GetTaskReport(id, "json");
          }

          public JObject GetTaskReport(int id, string type)
          {
               string uri = "/task/report/" + id + "/" + type;
               return _session.ExecuteCommand(uri, "GET");
          }

          public void Dispose()
          {
               _session = null;
          }
     }

     public class FileParameter
     {
          public byte[] File { get; set; }
          public string FileName { get; set; }
          public string ContentType { get; set; }

          public FileParameter(byte[] file, string filename, string contenttype)
          {
               File = file;
               FileName = filename;
               ContentType = contenttype;
          }
     }

     public abstract class Task
     {
          protected Task (JToken token)
          {
               if (token != null)
               {
                    this.AddedOn = DateTime.Parse((string)token["added_on"]);

                    if (token["completed_on"].Type != JTokenType.Null)
                         this.CompletedOn = DateTime.Parse(token["completed_on"].ToObject<string>());

                    this.Machine = (string)token["machine"];
                    this.Errors = token["errors"].ToObject<ArrayList>();
                    this.Custom = (string)token["custom"];
                    this.EnableEnforceTimeout = (bool)token["enforce_timeout"];
                    this.EnableMemoryDump = (bool)token["memory"];
                    this.Guest = token["guest"];
                    this.ID = (int)token["id"];
                    this.Options = token["options"].ToString();
                    this.Package = (string)token["package"];
                    this.Platform = (string)token["platform"];
                    this.Priority = (int)token["priority"];
                    this.SampleID = (int)token["sample_id"];
                    this.Status = (string)token["status"];
                    this.Target = (string)token["target"];
                    this.Timeout = (int)token["timeout"];
               }
          }

          public string Package { get; set; }
          public int Timeout { get; set; }
          public string Options { get; set; }
          public string Machine { get; set; }
          public string Platform { get; set; }
          public string Custom { get; set; }
          public bool EnableMemoryDump { get; set; }
          public bool EnableEnforceTimeout { get; set; }
          public ArrayList Errors { get; set; }
          public string Target { get; set; }
          public int SampleID { get; set; }
          public JToken Guest { get; set; }
          public int Priority { get; set; }
          public string Status { get; set; }
          public int ID { get; set; }
          public DateTime AddedOn { get; set; }
          public DateTime CompletedOn { get; set; }
     }
     public class FileTask : Task
     {
          public FileTask() : base(null) { }
          public FileTask(JToken dict) : base(dict) { }
          public string Filepath { get; set; }
     }

     public static class TaskFactory
     {
          public static Task CreateTask(JToken dict)
          {
               Task task = null;
               switch((string)dict["category"])
               {
                    case "file":
                         task = new FileTask(dict);
                         break;
                    default:
                         throw new Exception("Don't know category: " + dict["category"]);
               }

               return task;
          }
     }

}

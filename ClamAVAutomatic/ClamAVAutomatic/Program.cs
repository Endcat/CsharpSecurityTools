using System;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.IO;

namespace ClamAVAutomatic
{
     class Program
     {
          static void Main(string[] args)
          {
               // ClamAV Automator
               using (ClamEngine e = new ClamEngine())
               {
                    foreach (string file in args)
                    {
                         ClamResult result = e.ScanFile(file);

                         if (result != null && result.ReturnCode == ClamReturnCode.CL_VIRUS)
                              Console.WriteLine("Found: " + result.VirusName);
                         else
                              Console.WriteLine("File Clean!");
                    }
               }// engine is disposed of here and the allocated engine freed automatically
          }

          static void ClamdTestMain(string[] args)
          {
               ClamdSession session = new ClamdSession("127.0.0.1", 3310);
               ClamdManager manager = new ClamdManager(session);

               Console.WriteLine(manager.GetVersion());

               foreach (string path in args)
                    Console.WriteLine(manager.Scan(path));
          }
     }

     [Flags]
     public enum ClamDatabaseOptions
     {
          CL_DB_PHISHING = 0x2,
          CL_DB_PHISHING_URLS = 0x8,
          CL_DB_BYTECODE = 0x2000,
          CL_DB_STDOPT = (CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE),


     }

     public enum ClamReturnCode
     {
          CL_CLEAN = 0x0,
          CL_SUCCESS = 0x0,
          CL_VIRUS = 0x1
     }

     [Flags]
     public enum ClamScanOptions
     {
          CL_SCAN_ARCHIVE = 0x1,
          CL_SCAN_MAIL = 0x2,
          CL_SCAN_OLE2 = 0x4,
          CL_SCAN_HTML = 0x10,
          CL_SCAN_PE = 0x20,
          CL_SCAN_ALGORITHMIC = 0x200,
          CL_SCAN_ELF = 0x2000,
          CL_SCAN_PDF = 0x4000,
          CL_SCAN_STDOPT = (CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_PDF | CL_SCAN_HTML | CL_SCAN_PE | CL_SCAN_ALGORITHMIC | CL_SCAN_ELF)
     }

     public class ClamResult
     {
          public ClamReturnCode ReturnCode { get; set; }
          public string VirusName { get; set; }
          public string FullPath { get; set; }
     }

     static class ClamBindings
     {
          const string _clamLibPath = "Enter Your Path to libclamav";

          [DllImport(_clamLibPath)]
          public extern static ClamReturnCode cl_unit(uint options);

          [DllImport(_clamLibPath)]
          public extern static IntPtr cl_engine_new();

          [DllImport(_clamLibPath)]
          public extern static ClamReturnCode cl_engine_free(IntPtr engine);

          [DllImport(_clamLibPath)]
          public extern static IntPtr cl_retdbdir();

          [DllImport(_clamLibPath)]
          public extern static ClamReturnCode cl_load(string path, IntPtr engine, ref uint signo, uint options);

          [DllImport(_clamLibPath)]
          public extern static ClamReturnCode cl_scanfile(string path, ref IntPtr virusName, ref ulong scanned, IntPtr engine, uint options);

          [DllImport(_clamLibPath)]
          public extern static ClamReturnCode cl_engine_compile(IntPtr engine);

     }

     public class ClamEngine : IDisposable
     {
          private IntPtr engine;

          public ClamEngine()
          {
               ClamReturnCode ret = ClamBindings.cl_unit((uint)ClamDatabaseOptions.CL_DB_STDOPT);

               if (ret != ClamReturnCode.CL_SUCCESS)
                    throw new Exception("Expected CL_SUCCESS, got " + ret);

               engine = ClamBindings.cl_engine_new();

               try
               {
                    string dbdir = Marshal.PtrToStringAnsi(ClamBindings.cl_retdbdir());
                    uint signatureCount = 0;

                    ret = ClamBindings.cl_load(dbdir, engine, ref signatureCount, (uint)ClamScanOptions.CL_SCAN_STDOPT);

                    if (ret != ClamReturnCode.CL_SUCCESS)
                         throw new Exception("Expected CL_SUCCESS, got " + ret);

                    ret = (ClamReturnCode)ClamBindings.cl_engine_compile(engine);

                    if (ret != ClamReturnCode.CL_SUCCESS)
                         throw new Exception("Expected CL_SUCCESS, got " + ret);
               }
               catch
               {
                    ret = ClamBindings.cl_engine_free(engine);

                    if (ret != ClamReturnCode.CL_SUCCESS)
                         Console.Error.WriteLine("Freeing allocated engine failed");

                    throw;
               }
          }

          public ClamResult ScanFile(string filepath, uint options = (uint)ClamScanOptions.CL_SCAN_STDOPT)
          {
               ulong scanned = 0;
               IntPtr vname = (IntPtr)null;
               ClamReturnCode ret = ClamBindings.cl_scanfile(filepath, ref vname, ref scanned, engine, options);

               if (ret == ClamReturnCode.CL_VIRUS)
               {
                    string virus = Marshal.PtrToStringAnsi(vname);

                    ClamResult result = new ClamResult();
                    result.ReturnCode = ret;
                    result.VirusName = virus;
                    result.FullPath = filepath;

                    return result;
               }
               else if (ret == ClamReturnCode.CL_CLEAN)
                    return new ClamResult() { ReturnCode = ret, FullPath = filepath };
               else
                    throw new Exception("Expected either CL_CLEAN or CL_VIRUS, got: " + ret);
          }

          public void Dispose()
          {
               ClamReturnCode ret = ClamBindings.cl_engine_free(engine);

               if (ret != ClamReturnCode.CL_SUCCESS)
                    Console.Error.WriteLine("Freeing allocated engine failed");
          }
     }

     public class ClamdSession
     {
          private string _host = null;
          private int _port;

          public ClamdSession(string host, int port)
          {
               _host = host;
               _port = port;
          }

          public string Execute(string command)
          {
               string resp = string.Empty;
               using (TcpClient client = new TcpClient(_host,_port))
               {
                    using (NetworkStream stream = client.GetStream())
                    {
                         byte[] data = System.Text.Encoding.ASCII.GetBytes(command);
                         stream.Write(data, 0, data.Length);

                         using (StreamReader rdr = new StreamReader(stream))
                              resp = rdr.ReadToEnd();
                    }
               }

               return resp;
          }
     }

     public class ClamdManager
     {
          private ClamdSession _session = null;

          public ClamdManager(ClamdSession session)
          {
               _session = session;
          }
          
          public string GetVersion()
          {
               return _session.Execute("VERSION");
          }

          public string Scan(string path)
          {
               return _session.Execute("SCAN " + path);
          }
     }
}

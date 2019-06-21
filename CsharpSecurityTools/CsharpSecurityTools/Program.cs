using System;
using System.Runtime.InteropServices;

namespace CsharpSecurityTools
{
     class MainClass
     {
          [DllImport("user32", CharSet = CharSet.Auto)]
          static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

          [DllImport("libc")]
          static extern void printf(string message);
          static void Main(string[] args)
          {
               OperatingSystem os = Environment.OSVersion;
               if (os.Platform == PlatformID.Win32NT)
               {
                    MessageBox(IntPtr.Zero, "Hello!", "Hello", 0);
               }
               else
               {
                    printf("Hello Miao!");
               }
               //Console.WriteLine("Hello World!");
          }
     }
}

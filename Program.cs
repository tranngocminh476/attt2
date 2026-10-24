using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

// ===== BÀI 1: AES-256 (CBC + PKCS7), xử lý file theo stream nên chạy được file hàng GB =====
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

const int Buf = 1 << 20; // 1 MB
byte[]? key = null;

while (true)
{
    Console.WriteLine("\n===== AES =====");
    Console.WriteLine(" 1. Sinh khoá AES (128/192/256 bit)");
    Console.WriteLine(" 2. Lưu khoá ra file");
    Console.WriteLine(" 3. Import khoá từ file");
    Console.WriteLine(" 4. Mã hoá văn bản");
    Console.WriteLine(" 5. Giải mã văn bản");
    Console.WriteLine(" 6. Mã hoá file");
    Console.WriteLine(" 7. Giải mã file");
    Console.WriteLine(" 8. So sánh 2 file theo byte");
    Console.WriteLine(" 9. Tạo file test dung lượng lớn");
    Console.WriteLine("10. Benchmark trọn gói (mã hoá -> giải mã -> so sánh)");
    Console.WriteLine(" 0. Thoát");
    string c = Ask("Chọn: ");
    try
    {
        switch (c)
        {
            case "1":
                int bits = int.TryParse(Ask("Độ dài khoá (128/192/256) [256]: "), out var b) ? b : 256;
                key = RandomNumberGenerator.GetBytes(bits / 8);
                Console.WriteLine($"Khoá ({key.Length} byte, base64): {Convert.ToBase64String(key)}");
                break;
            case "2":
                NeedKey();
                File.WriteAllText(Ask("Đường dẫn file lưu khoá: "), Convert.ToBase64String(key!));
                Console.WriteLine("Đã lưu.");
                break;
            case "3":
                var k = Convert.FromBase64String(File.ReadAllText(Ask("Đường dẫn file khoá: ")).Trim());
                if (k.Length is not (16 or 24 or 32)) throw new Exception("Khoá không hợp lệ (phải 16/24/32 byte).");
                key = k;
                Console.WriteLine($"Đã import khoá {k.Length * 8} bit.");
                break;
            case "4":
                NeedKey();
                Console.WriteLine("Bản mã (base64 của IV + ciphertext):\n" + EncryptText(Ask("Văn bản: ")));
                break;
            case "5":
                NeedKey();
                Console.WriteLine("Bản rõ: " + DecryptText(Ask("Bản mã base64: ")));
                break;
            case "6":
                NeedKey();
                string src = Ask("File nguồn: "), dst = Ask("File đích (đã mã hoá): ");
                Console.WriteLine($"Thời gian mã hoá: {Time(() => EncryptFile(src, dst)):F3} s");
                break;
            case "7":
                NeedKey();
                string s2 = Ask("File đã mã hoá: "), d2 = Ask("File đích (giải mã): ");
                Console.WriteLine($"Thời gian giải mã: {Time(() => DecryptFile(s2, d2)):F3} s");
                break;
            case "8":
                Console.WriteLine(CompareFiles(Ask("File A: "), Ask("File B: ")) ? "GIỐNG NHAU từng byte." : "KHÁC NHAU.");
                break;
            case "9":
                string tp = Ask("Đường dẫn file test: ");
                long mb = long.Parse(Ask("Dung lượng (MB), vd 2048 = 2GB: "));
                Console.WriteLine($"Tạo file mất {Time(() => GenTestFile(tp, mb)):F3} s");
                break;
            case "10":
                NeedKey();
                Benchmark(Ask("File nguồn: "));
                break;
            case "0": return;
        }
    }
    catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
}

// ---------------- hàm hỗ trợ ----------------
string Ask(string m) { Console.Write(m); return (Console.ReadLine() ?? "").Trim().Trim('"'); }
void NeedKey() { if (key == null) throw new Exception("Chưa có khoá. Hãy sinh (1) hoặc import (3) khoá."); }
double Time(Action a) { var sw = Stopwatch.StartNew(); a(); sw.Stop(); return sw.Elapsed.TotalSeconds; }

string EncryptText(string text)
{
    using var aes = Aes.Create();
    aes.Key = key!; aes.GenerateIV();
    byte[] ct = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), aes.IV);
    return Convert.ToBase64String(aes.IV.Concat(ct).ToArray());
}

string DecryptText(string b64)
{
    byte[] all = Convert.FromBase64String(b64);
    using var aes = Aes.Create();
    aes.Key = key!;
    byte[] pt = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16));
    return Encoding.UTF8.GetString(pt);
}

void EncryptFile(string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key!; aes.GenerateIV();
    using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
    fout.Write(aes.IV);                                   // 16 byte đầu file = IV
    using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fin.CopyTo(cs, Buf);
}

void DecryptFile(string src, string dst)
{
    using var aes = Aes.Create();
    aes.Key = key!;
    using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
    byte[] iv = new byte[16];
    fin.ReadExactly(iv);
    using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
    using var cs = new CryptoStream(fin, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Read);
    cs.CopyTo(fout, Buf);
}

bool CompareFiles(string a, string b)
{
    using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
    using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
    Console.WriteLine($"Kích thước A = {fa.Length:N0} byte, B = {fb.Length:N0} byte");
    if (fa.Length != fb.Length) return false;
    byte[] ba = new byte[Buf], bb = new byte[Buf];
    long offset = 0;
    int n;
    while ((n = fa.Read(ba, 0, Buf)) > 0)
    {
        fb.ReadExactly(bb, 0, n);
        if (!ba.AsSpan(0, n).SequenceEqual(bb.AsSpan(0, n)))
        {
            int i = ba.AsSpan(0, n).CommonPrefixLength(bb.AsSpan(0, n));
            Console.WriteLine($"Khác nhau đầu tiên tại byte {offset + i:N0}");
            return false;
        }
        offset += n;
    }
    return true;
}

void GenTestFile(string path, long mb)
{
    using var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
    byte[] buf = new byte[Buf];
    for (long i = 0; i < mb; i++) { RandomNumberGenerator.Fill(buf); f.Write(buf); }
}

void Benchmark(string src)
{
    string enc = src + ".enc", dec = src + ".dec";
    double mbSize = new FileInfo(src).Length / 1024.0 / 1024.0;
    double tE = Time(() => EncryptFile(src, enc));
    double tD = Time(() => DecryptFile(enc, dec));
    bool same = false;
    double tC = Time(() => same = CompareFiles(src, dec));
    Console.WriteLine("\n--- KẾT QUẢ ---");
    Console.WriteLine($"Kích thước nguồn : {mbSize:N1} MB");
    Console.WriteLine($"Kích thước mã hoá: {new FileInfo(enc).Length / 1024.0 / 1024.0:N1} MB (= nguồn + padding + 16 byte IV)");
    Console.WriteLine($"Mã hoá : {tE:F3} s  ({mbSize / tE:F1} MB/s)");
    Console.WriteLine($"Giải mã: {tD:F3} s  ({mbSize / tD:F1} MB/s)");
    Console.WriteLine($"So sánh: {tC:F3} s -> {(same ? "GIỐNG NHAU 100%" : "KHÁC NHAU")}");
    Console.WriteLine($"AES-NI phần cứng: {(System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported ? "có" : "không")}");
}

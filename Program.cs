using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// ===== BÀI 2: RSA / PEM / SHA-256 / Chữ ký số =====
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

RSA? rsa = null;

while (true)
{
    Console.WriteLine("\n===== RSA =====");
    Console.WriteLine(" 1. Sinh cặp khoá");
    Console.WriteLine(" 2. Xuất cặp khoá ra file PEM");
    Console.WriteLine(" 3. Xem PEM + giải thích cấu trúc byte (ASN.1 DER)");
    Console.WriteLine(" 4. Nhập PEM -> hiện n, e (public) / n, e, d, p, q... (private)");
    Console.WriteLine(" 5. Mã hoá (public.pem, dữ liệu <= 190 byte) -> file base64");
    Console.WriteLine(" 6. Giải mã (private.pem, file base64) + so sánh với nguồn");
    Console.WriteLine(" 7. Đánh giá tốc độ: public key (e nhỏ) vs private key (d lớn)");
    Console.WriteLine(" 8. SHA-256 + đánh giá hiệu ứng thác đổ (avalanche)");
    Console.WriteLine(" 9. Chữ ký số: PKCS#1 v1.5 (tất định) vs PSS (ngẫu nhiên hoá)");
    Console.WriteLine(" 0. Thoát");
    try
    {
        switch (Ask("Chọn: "))
        {
            case "1":
                int bits = int.TryParse(Ask("Độ dài khoá [2048]: "), out var b) ? b : 2048;
                rsa?.Dispose();
                rsa = RSA.Create(bits);
                Console.WriteLine($"Đã sinh khoá RSA {bits} bit.");
                break;
            case "2":
                if (rsa == null) throw new Exception("Chưa có khoá, chọn 1 trước.");
                File.WriteAllText("public.pem", rsa.ExportSubjectPublicKeyInfoPem());   // "PUBLIC KEY"  (X.509 SPKI)
                File.WriteAllText("private.pem", rsa.ExportRSAPrivateKeyPem());          // "RSA PRIVATE KEY" (PKCS#1)
                Console.WriteLine("Đã ghi public.pem và private.pem vào thư mục hiện tại.");
                break;
            case "3": ViewPem(Ask("File PEM: ")); break;
            case "4": ShowKey(Ask("File PEM: ")); break;
            case "5": Encrypt(); break;
            case "6": Decrypt(); break;
            case "7": SpeedTest(); break;
            case "8": HashDemo(); break;
            case "9": SignDemo(); break;
            case "0": return;
        }
    }
    catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
}

string Ask(string m) { Console.Write(m); return (Console.ReadLine() ?? "").Trim().Trim('"'); }
string Hex(byte[] d) => Convert.ToHexString(d);
string Short(byte[] d) => d.Length <= 24 ? Hex(d) : Hex(d[..12]) + "..." + Hex(d[^6..]) + $" ({d.Length} byte)";

// ---------- 3. Xem PEM + dump ASN.1 ----------
void ViewPem(string path)
{
    string pem = File.ReadAllText(path);
    Console.WriteLine(pem);
    string label = pem.Split('\n')[0].Trim();
    Console.WriteLine($"Header: {label}  (PUBLIC KEY = X.509 SubjectPublicKeyInfo, RSA PRIVATE KEY = PKCS#1, PRIVATE KEY = PKCS#8)");
    string body = string.Concat(pem.Split('\n').Where(l => !l.StartsWith("-----"))).Trim();
    byte[] der = Convert.FromBase64String(body);
    Console.WriteLine($"Base64 -> {der.Length} byte DER. Cấu trúc TLV (Tag-Length-Value):");
    DumpAsn1(der, 0, der.Length, 0);
}

void DumpAsn1(byte[] d, int p, int end, int depth)
{
    while (p < end)
    {
        int start = p;
        byte tag = d[p++];
        int len = d[p++];
        if ((len & 0x80) != 0) { int n = len & 0x7F; len = 0; for (int i = 0; i < n; i++) len = (len << 8) | d[p++]; }
        string name = tag switch
        {
            0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x03 => "BIT STRING", 0x04 => "OCTET STRING",
            0x05 => "NULL", 0x06 => "OBJECT IDENTIFIER", _ => $"tag 0x{tag:X2}"
        };
        string note = "";
        if (tag == 0x02) note = " = " + Short(d[p..(p + len)]);
        if (tag == 0x06) note = " = " + Hex(d[p..(p + len)]) + (Hex(d[p..(p + len)]) == "2A864886F70D010101" ? " (rsaEncryption 1.2.840.113549.1.1.1)" : "");
        Console.WriteLine($"{new string(' ', depth * 2)}[offset {start}] {name} (0x{tag:X2}), length={len}{note}");
        if (tag == 0x30 || tag == 0x04) DumpAsn1(d, p, p + len, depth + 1);
        else if (tag == 0x03 && len > 1) DumpAsn1(d, p + 1, p + len, depth + 1); // bỏ byte "unused bits"
        p += len;
    }
    if (depth == 0)
        Console.WriteLine("\nPublic (SPKI): SEQ{ SEQ{OID rsaEncryption, NULL}, BIT STRING{ SEQ{ n, e } } }\n" +
                          "Private (PKCS#1): SEQ{ version, n, e, d, p, q, d mod (p-1), d mod (q-1), q^-1 mod p }");
}

// ---------- 4. Nhập PEM ----------
void ShowKey(string path)
{
    using var r = RSA.Create();
    r.ImportFromPem(File.ReadAllText(path));
    RSAParameters pr; bool priv = true;
    try { pr = r.ExportParameters(true); } catch { pr = r.ExportParameters(false); priv = false; }
    Console.WriteLine(priv ? "== PRIVATE KEY ==" : "== PUBLIC KEY ==");
    Console.WriteLine($"n ({pr.Modulus!.Length * 8} bit) = {Hex(pr.Modulus)}");
    Console.WriteLine($"e = {new BigInteger(pr.Exponent!, true, true)}  (hex {Hex(pr.Exponent!)})");
    if (priv)
    {
        Console.WriteLine($"d  ({pr.D!.Length * 8} bit) = {Hex(pr.D)}");
        Console.WriteLine($"p  = {Hex(pr.P!)}\nq  = {Hex(pr.Q!)}");
        Console.WriteLine($"dp = {Hex(pr.DP!)}\ndq = {Hex(pr.DQ!)}\nqinv = {Hex(pr.InverseQ!)}");
    }
}

// ---------- 5. Mã hoá ----------
// OAEP-SHA256: tối đa k - 2*32 - 2 = 256 - 66 = 190 byte với RSA-2048 (đúng với đề: khoá AES 32 byte nằm trong giới hạn).
void Encrypt()
{
    using var r = RSA.Create();
    r.ImportFromPem(File.ReadAllText(Ask("File public.pem: ")));
    string input = Ask("Dữ liệu (base64, vd khoá AES 32 byte) hoặc đường dẫn file chứa base64: ");
    if (File.Exists(input)) input = File.ReadAllText(input).Trim();
    byte[] data = Convert.FromBase64String(input);
    int max = r.KeySize / 8 - 66;
    if (data.Length > max) throw new Exception($"Dữ liệu {data.Length} byte > tối đa {max} byte.");
    string outB64 = Convert.ToBase64String(r.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
    string outPath = Ask("File lưu bản mã: ");
    File.WriteAllText(outPath, outB64);
    Console.WriteLine($"Đã mã hoá {data.Length} byte -> {outB64}");
}

// ---------- 6. Giải mã ----------
void Decrypt()
{
    using var r = RSA.Create();
    r.ImportFromPem(File.ReadAllText(Ask("File private.pem: ")));
    byte[] plain = r.Decrypt(Convert.FromBase64String(File.ReadAllText(Ask("File bản mã (base64): ")).Trim()),
                             RSAEncryptionPadding.OaepSHA256);
    string got = Convert.ToBase64String(plain);
    Console.WriteLine($"Kết quả giải mã (base64): {got}");
    string orig = Ask("Dữ liệu gốc (base64 hoặc đường dẫn file) để so sánh [Enter = bỏ qua]: ");
    if (orig != "")
    {
        if (File.Exists(orig)) orig = File.ReadAllText(orig).Trim();
        Console.WriteLine(Convert.FromBase64String(orig).AsSpan().SequenceEqual(plain) ? "=> TRÙNG KHỚP với dữ liệu gốc." : "=> KHÁC dữ liệu gốc!");
    }
}

// ---------- 7. Tốc độ ----------
void SpeedTest()
{
    foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
    {
        using var full = RSA.Create(bits);
        using var pub = RSA.Create();
        pub.ImportParameters(full.ExportParameters(false));        // chỉ có n, e
        byte[] data = RandomNumberGenerator.GetBytes(32);
        byte[] ct = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        full.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);          // khởi động

        int nPub = 2000, nPriv = 200;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < nPub; i++) pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        double tPub = sw.Elapsed.TotalMilliseconds / nPub;
        sw.Restart();
        for (int i = 0; i < nPriv; i++) full.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
        double tPriv = sw.Elapsed.TotalMilliseconds / nPriv;

        var pr = full.ExportParameters(true);
        Console.WriteLine($"RSA-{bits}: e = {new BigInteger(pr.Exponent!, true, true)} ({new BigInteger(pr.Exponent!, true, true).GetBitLength()} bit), d = {pr.D!.Length * 8} bit" +
                          $" | Mã hoá (public): {tPub:F4} ms | Giải mã (private): {tPriv:F4} ms | private chậm gấp {tPriv / tPub:F1} lần");
    }
}

// ---------- 8. SHA-256 ----------
void HashDemo()
{
    string a = Ask("Chuỗi 1: "), b = Ask("Chuỗi 2 (sửa rất ít, vd đổi 1 ký tự): ");
    byte[] ha = SHA256.HashData(Encoding.UTF8.GetBytes(a)), hb = SHA256.HashData(Encoding.UTF8.GetBytes(b));
    Console.WriteLine($"SHA256(1) = {Hex(ha)}\nSHA256(2) = {Hex(hb)}");
    int diff = ha.Zip(hb, (x, y) => BitOperations_PopCount((byte)(x ^ y))).Sum();
    Console.WriteLine($"Số bit khác nhau: {diff}/256 = {diff / 2.56:F1}%  (lý thuyết ≈ 50% => hiệu ứng thác đổ)");
}
int BitOperations_PopCount(byte x) => System.Numerics.BitOperations.PopCount(x);

// ---------- 9. Chữ ký số ----------
void SignDemo()
{
    using var r = RSA.Create(2048);
    byte[] data = Encoding.UTF8.GetBytes(Ask("Dữ liệu cần ký: "));

    Console.WriteLine("\n-- PKCS#1 v1.5: ký 3 lần cùng dữ liệu, cùng khoá --");
    for (int i = 0; i < 3; i++)
    {
        byte[] s = r.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Console.WriteLine($"  lần {i + 1}: {Convert.ToBase64String(s)[..48]}...  verify={r.VerifyData(data, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)}");
    }
    Console.WriteLine("-- RSASSA-PSS (salt ngẫu nhiên): ký 3 lần cùng dữ liệu, cùng khoá --");
    for (int i = 0; i < 3; i++)
    {
        byte[] s = r.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Console.WriteLine($"  lần {i + 1}: {Convert.ToBase64String(s)[..48]}...  verify={r.VerifyData(data, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)}");
    }
    Console.WriteLine("=> PKCS#1 v1.5 cho chữ ký GIỐNG nhau; PSS cho chữ ký KHÁC nhau mỗi lần nhưng đều xác thực đúng.");
}

using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

class MainForm : Form
{
    const int Buf = 1 << 20;
    byte[]? key;
    RSA? rsa;

    public MainForm()
    {
        Text = "An toàn & Bảo mật thông tin - AES / RSA / SHA-256 / Chữ ký số";
        Width = 1100; Height = 700; StartPosition = FormStartPosition.CenterScreen;
        var tabs = new TabControl { Dock = DockStyle.Fill };
        Controls.Add(tabs);
        BuildAes(tabs); BuildRsa(tabs); BuildHash(tabs); BuildSign(tabs);
    }

    // ---------- tiện ích giao diện ----------
    (TextBox input, TextBox log, FlowLayoutPanel bar, TabPage page) MakeTab(string title, string hint)
    {
        var page = new TabPage(title);
        var log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9) };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        var input = new TextBox { Multiline = true, Dock = DockStyle.Top, Height = 55, ScrollBars = ScrollBars.Vertical, PlaceholderText = hint };
        page.Controls.Add(log); page.Controls.Add(bar); page.Controls.Add(input);
        return (input, log, bar, page);
    }

    void Btn(FlowLayoutPanel bar, string text, TextBox log, Func<Task<string?>> work)
    {
        var b = new Button { Text = text, AutoSize = true };
        b.Click += async (_, _) =>
        {
            bar.Enabled = false;
            try { var r = await work(); if (r != null) log.AppendText(r + "\r\n\r\n"); }
            catch (Exception ex) { log.AppendText("Lỗi: " + ex.Message + "\r\n\r\n"); }
            finally { bar.Enabled = true; }
        };
        bar.Controls.Add(b);
    }

    string? Open(string filter = "Tất cả|*.*") { using var d = new OpenFileDialog { Filter = filter }; return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null; }
    string? Save(string name) { using var d = new SaveFileDialog { FileName = name }; return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null; }
    static double Time(Action a) { var sw = Stopwatch.StartNew(); a(); return sw.Elapsed.TotalSeconds; }
    static string Hex(byte[] d) => Convert.ToHexString(d);
    static string Short(byte[] d) => d.Length <= 24 ? Hex(d) : Hex(d[..12]) + "..." + Hex(d[^6..]) + $" ({d.Length} byte)";
    void NeedKey() { if (key == null) throw new Exception("Chưa có khoá AES. Hãy sinh hoặc import khoá."); }
    void NeedRsa() { if (rsa == null) throw new Exception("Chưa có cặp khoá RSA. Hãy bấm 'Sinh cặp khoá'."); }

    // ================= BÀI 1: AES =================
    void BuildAes(TabControl tabs)
    {
        var (inp, log, bar, page) = MakeTab("Bài 1 - AES", "Nhập văn bản cần mã hoá, hoặc chuỗi base64 cần giải mã");
        tabs.TabPages.Add(page);
        var cb = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 60 };
        cb.Items.AddRange(new object[] { "128", "192", "256" }); cb.SelectedIndex = 2;
        var mb = new NumericUpDown { Minimum = 1, Maximum = 1000000, Value = 1024, Width = 80 };
        bar.Controls.Add(new Label { Text = "Khoá (bit):", AutoSize = true, Margin = new Padding(3, 8, 0, 0) });
        bar.Controls.Add(cb);

        Btn(bar, "1. Sinh khoá", log, async () => { key = RandomNumberGenerator.GetBytes(int.Parse(cb.Text) / 8); return $"Khoá AES-{key.Length * 8} (base64): {Convert.ToBase64String(key)}"; });
        Btn(bar, "2. Lưu khoá", log, async () => { NeedKey(); var p = Save("aes.key"); if (p == null) return null; File.WriteAllText(p, Convert.ToBase64String(key!)); return "Đã lưu khoá: " + p; });
        Btn(bar, "3. Import khoá", log, async () =>
        {
            var p = Open(); if (p == null) return null;
            var k = Convert.FromBase64String(File.ReadAllText(p).Trim());
            if (k.Length is not (16 or 24 or 32)) throw new Exception("Khoá phải dài 16/24/32 byte.");
            key = k; return $"Đã import khoá {k.Length * 8} bit.";
        });
        Btn(bar, "4. Mã hoá văn bản", log, async () => { NeedKey(); return "Bản mã (base64 = IV + ciphertext):\r\n" + EncText(inp.Text); });
        Btn(bar, "5. Giải mã văn bản", log, async () => { NeedKey(); return "Bản rõ: " + DecText(inp.Text.Trim()); });
        Btn(bar, "6. Mã hoá file", log, async () =>
        {
            NeedKey(); var s = Open(); if (s == null) return null; var d = Save(Path.GetFileName(s) + ".enc"); if (d == null) return null;
            double t = await Task.Run(() => Time(() => EncFile(s, d))); return $"Mã hoá {s}\r\nThời gian: {t:F3} s";
        });
        Btn(bar, "7. Giải mã file", log, async () =>
        {
            NeedKey(); var s = Open(); if (s == null) return null; var d = Save("giaima_" + Path.GetFileNameWithoutExtension(s)); if (d == null) return null;
            double t = await Task.Run(() => Time(() => DecFile(s, d))); return $"Giải mã {s}\r\nThời gian: {t:F3} s";
        });
        Btn(bar, "8. So sánh 2 file", log, async () =>
        {
            var a = Open(); if (a == null) return null; var b = Open(); if (b == null) return null;
            return await Task.Run(() => { string r = ""; bool same = false; double t = Time(() => same = Cmp(a, b, out r)); return r + (same ? "=> GIỐNG NHAU từng byte" : "=> KHÁC NHAU") + $" ({t:F3} s)"; });
        });
        bar.Controls.Add(new Label { Text = "File test (MB):", AutoSize = true, Margin = new Padding(12, 8, 0, 0) });
        bar.Controls.Add(mb);
        Btn(bar, "9. Tạo file test", log, async () =>
        {
            var p = Save("test.bin"); if (p == null) return null; long n = (long)mb.Value;
            double t = await Task.Run(() => Time(() => Gen(p, n))); return $"Đã tạo {p} ({n} MB) trong {t:F3} s";
        });
        Btn(bar, "10. Benchmark trọn gói", log, async () =>
        {
            NeedKey(); var s = Open(); if (s == null) return null;
            return await Task.Run(() =>
            {
                string e = s + ".enc", d = s + ".dec"; double size = new FileInfo(s).Length / 1048576.0;
                double tE = Time(() => EncFile(s, e)), tD = Time(() => DecFile(e, d));
                string r = ""; bool same = false; double tC = Time(() => same = Cmp(s, d, out r));
                return $"--- KẾT QUẢ BENCHMARK ---\r\nNguồn: {size:N1} MB | File mã hoá: {new FileInfo(e).Length / 1048576.0:N1} MB\r\n" +
                       $"Mã hoá : {tE:F3} s ({size / tE:F1} MB/s)\r\nGiải mã: {tD:F3} s ({size / tD:F1} MB/s)\r\n" +
                       $"So sánh byte: {tC:F3} s -> {(same ? "GIỐNG NHAU 100%" : "KHÁC NHAU")}\r\n{r}";
            });
        });
    }

    string EncText(string t)
    {
        using var aes = Aes.Create(); aes.Key = key!; aes.GenerateIV();
        return Convert.ToBase64String(aes.IV.Concat(aes.EncryptCbc(Encoding.UTF8.GetBytes(t), aes.IV)).ToArray());
    }
    string DecText(string b64)
    {
        var all = Convert.FromBase64String(b64); using var aes = Aes.Create(); aes.Key = key!;
        return Encoding.UTF8.GetString(aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16)));
    }
    void EncFile(string src, string dst)
    {
        using var aes = Aes.Create(); aes.Key = key!; aes.GenerateIV();
        using var fi = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
        using var fo = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
        fo.Write(aes.IV);
        using var cs = new CryptoStream(fo, aes.CreateEncryptor(), CryptoStreamMode.Write);
        fi.CopyTo(cs, Buf);
    }
    void DecFile(string src, string dst)
    {
        using var aes = Aes.Create(); aes.Key = key!;
        using var fi = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
        var iv = new byte[16]; fi.ReadExactly(iv);
        using var fo = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, Buf);
        using var cs = new CryptoStream(fi, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Read);
        cs.CopyTo(fo, Buf);
    }
    static bool Cmp(string a, string b, out string info)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, Buf, FileOptions.SequentialScan);
        info = $"Kích thước A = {fa.Length:N0} byte, B = {fb.Length:N0} byte\r\n";
        if (fa.Length != fb.Length) return false;
        byte[] x = new byte[Buf], y = new byte[Buf]; long off = 0; int n;
        while ((n = fa.Read(x, 0, Buf)) > 0)
        {
            fb.ReadExactly(y, 0, n);
            if (!x.AsSpan(0, n).SequenceEqual(y.AsSpan(0, n))) { info += $"Khác đầu tiên tại byte {off + x.AsSpan(0, n).CommonPrefixLength(y.AsSpan(0, n)):N0}\r\n"; return false; }
            off += n;
        }
        return true;
    }
    static void Gen(string p, long mb)
    {
        using var f = new FileStream(p, FileMode.Create, FileAccess.Write, FileShare.None, Buf); var b = new byte[Buf];
        for (long i = 0; i < mb; i++) { RandomNumberGenerator.Fill(b); f.Write(b); }
    }

    // ================= BÀI 2: RSA =================
    void BuildRsa(TabControl tabs)
    {
        var (inp, log, bar, page) = MakeTab("Bài 2 - RSA", "Dữ liệu cần mã hoá RSA ở dạng base64 (<= 190 byte, vd khoá AES 32 byte) / dữ liệu gốc để so sánh khi giải mã");
        tabs.TabPages.Add(page);
        var cb = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 70 };
        cb.Items.AddRange(new object[] { "1024", "2048", "3072", "4096" }); cb.SelectedIndex = 1;
        bar.Controls.Add(new Label { Text = "Khoá (bit):", AutoSize = true, Margin = new Padding(3, 8, 0, 0) });
        bar.Controls.Add(cb);

        Btn(bar, "1. Sinh cặp khoá", log, async () => { rsa?.Dispose(); int n = int.Parse(cb.Text); rsa = await Task.Run(() => RSA.Create(n)); return $"Đã sinh cặp khoá RSA-{n}."; });
        Btn(bar, "2. Xuất PEM", log, async () =>
        {
            NeedRsa(); using var d = new FolderBrowserDialog(); if (d.ShowDialog(this) != DialogResult.OK) return null;
            File.WriteAllText(Path.Combine(d.SelectedPath, "public.pem"), rsa!.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(Path.Combine(d.SelectedPath, "private.pem"), rsa.ExportRSAPrivateKeyPem());
            return "Đã ghi public.pem và private.pem vào " + d.SelectedPath;
        });
        Btn(bar, "3. Xem PEM + ý nghĩa byte", log, async () =>
        {
            var p = Open("PEM|*.pem|Tất cả|*.*"); if (p == null) return null; string pem = File.ReadAllText(p);
            byte[] der = Convert.FromBase64String(string.Concat(pem.Split('\n').Where(l => !l.StartsWith("-----")).Select(l => l.Trim())));
            var sb = new StringBuilder(pem + $"\r\nBase64 -> {der.Length} byte DER. Cấu trúc TLV (Tag-Length-Value):\r\n"); Asn1(sb, der, 0, der.Length, 0);
            sb.Append("\r\nPublic (SPKI): SEQ{ SEQ{OID rsaEncryption, NULL}, BIT STRING{ SEQ{ n, e } } }\r\nPrivate (PKCS#1): SEQ{ version, n, e, d, p, q, dP, dQ, qInv }");
            return sb.ToString();
        });
        Btn(bar, "4. Nhập PEM -> n, e, d...", log, async () =>
        {
            var p = Open("PEM|*.pem|Tất cả|*.*"); if (p == null) return null;
            using var r = RSA.Create(); r.ImportFromPem(File.ReadAllText(p));
            RSAParameters pr; bool priv = true; try { pr = r.ExportParameters(true); } catch { pr = r.ExportParameters(false); priv = false; }
            var sb = new StringBuilder(priv ? "== PRIVATE KEY ==\r\n" : "== PUBLIC KEY ==\r\n");
            sb.Append($"n ({pr.Modulus!.Length * 8} bit) = {Hex(pr.Modulus)}\r\ne = {new BigInteger(pr.Exponent!, true, true)} (hex {Hex(pr.Exponent!)})");
            if (priv) sb.Append($"\r\nd = {Hex(pr.D!)}\r\np = {Hex(pr.P!)}\r\nq = {Hex(pr.Q!)}\r\ndP = {Hex(pr.DP!)}\r\ndQ = {Hex(pr.DQ!)}\r\nqInv = {Hex(pr.InverseQ!)}");
            return sb.ToString();
        });
        Btn(bar, "5. Mã hoá (chọn public.pem)", log, async () =>
        {
            var p = Open("PEM|*.pem|Tất cả|*.*"); if (p == null) return null;
            using var r = RSA.Create(); r.ImportFromPem(File.ReadAllText(p));
            var data = Convert.FromBase64String(inp.Text.Trim()); int max = r.KeySize / 8 - 66;
            if (data.Length > max) throw new Exception($"Dữ liệu {data.Length} byte > tối đa {max} byte (OAEP-SHA256).");
            string b64 = Convert.ToBase64String(r.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
            var o = Save("cipher.txt"); if (o != null) File.WriteAllText(o, b64);
            return $"Đã mã hoá {data.Length} byte -> {b64}";
        });
        Btn(bar, "6. Giải mã (private.pem + file base64)", log, async () =>
        {
            var p = Open("PEM|*.pem|Tất cả|*.*"); if (p == null) return null; var c = Open(); if (c == null) return null;
            using var r = RSA.Create(); r.ImportFromPem(File.ReadAllText(p));
            var plain = r.Decrypt(Convert.FromBase64String(File.ReadAllText(c).Trim()), RSAEncryptionPadding.OaepSHA256);
            string s = "Kết quả giải mã (base64): " + Convert.ToBase64String(plain);
            if (inp.Text.Trim() != "") s += Convert.FromBase64String(inp.Text.Trim()).AsSpan().SequenceEqual(plain) ? "\r\n=> TRÙNG KHỚP với dữ liệu gốc." : "\r\n=> KHÁC dữ liệu gốc!";
            return s;
        });
        Btn(bar, "7. Đánh giá tốc độ", log, async () => await Task.Run<string?>(() =>
        {
            var sb = new StringBuilder("Tốc độ trung bình (public: e = 65537 nhỏ | private: d lớn)\r\n");
            foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
            {
                using var full = RSA.Create(bits); using var pub = RSA.Create(); pub.ImportParameters(full.ExportParameters(false));
                var data = RandomNumberGenerator.GetBytes(32); var ct = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256); full.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
                var sw = Stopwatch.StartNew(); for (int i = 0; i < 2000; i++) pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256); double a = sw.Elapsed.TotalMilliseconds / 2000;
                sw.Restart(); for (int i = 0; i < 200; i++) full.Decrypt(ct, RSAEncryptionPadding.OaepSHA256); double b = sw.Elapsed.TotalMilliseconds / 200;
                sb.Append($"RSA-{bits}: mã hoá(public) {a:F4} ms | giải mã(private) {b:F4} ms | private chậm gấp {b / a:F1} lần\r\n");
            }
            return sb.ToString();
        }));
    }

    static void Asn1(StringBuilder sb, byte[] d, int p, int end, int depth)
    {
        while (p < end)
        {
            int start = p; byte tag = d[p++]; int len = d[p++];
            if ((len & 0x80) != 0) { int n = len & 0x7F; len = 0; for (int i = 0; i < n; i++) len = (len << 8) | d[p++]; }
            string name = tag switch { 0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x03 => "BIT STRING", 0x04 => "OCTET STRING", 0x05 => "NULL", 0x06 => "OID", _ => $"tag 0x{tag:X2}" };
            string note = tag == 0x02 || tag == 0x06 ? " = " + Short(d[p..(p + len)]) : "";
            if (tag == 0x06 && Hex(d[p..(p + len)]) == "2A864886F70D010101") note += " (rsaEncryption)";
            sb.Append($"{new string(' ', depth * 2)}[offset {start}] {name} (0x{tag:X2}), length={len}{note}\r\n");
            if (tag == 0x30 || tag == 0x04) Asn1(sb, d, p, p + len, depth + 1);
            else if (tag == 0x03 && len > 1) Asn1(sb, d, p + 1, p + len, depth + 1);
            p += len;
        }
    }

    // ================= SHA-256 =================
    void BuildHash(TabControl tabs)
    {
        var page = new TabPage("SHA-256");
        var out_ = new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, Font = new Font("Consolas", 10), ScrollBars = ScrollBars.Both };
        var b = new TextBox { Multiline = true, Dock = DockStyle.Top, Height = 70, PlaceholderText = "Dữ liệu 2 (sửa rất ít so với dữ liệu 1)" };
        var a = new TextBox { Multiline = true, Dock = DockStyle.Top, Height = 70, PlaceholderText = "Dữ liệu 1" };
        page.Controls.Add(out_); page.Controls.Add(b); page.Controls.Add(a); tabs.TabPages.Add(page);
        void Update(object? s, EventArgs e)
        {
            var ha = SHA256.HashData(Encoding.UTF8.GetBytes(a.Text)); var hb = SHA256.HashData(Encoding.UTF8.GetBytes(b.Text));
            int diff = ha.Zip(hb, (x, y) => BitOperations.PopCount((uint)(x ^ y))).Sum();
            out_.Text = $"SHA256(1) = {Hex(ha)}\r\nSHA256(2) = {Hex(hb)}\r\n\r\nSố bit băm khác nhau: {diff}/256 = {diff / 2.56:F1}%\r\n(Lý thuyết ~50% => hiệu ứng thác đổ: đổi đầu vào rất ít, băm đổi hoàn toàn)";
        }
        a.TextChanged += Update; b.TextChanged += Update; Update(null, EventArgs.Empty);
    }

    // ================= CHỮ KÝ SỐ =================
    void BuildSign(TabControl tabs)
    {
        var (inp, log, bar, page) = MakeTab("Chữ ký số", "Dữ liệu cần ký");
        tabs.TabPages.Add(page);
        string Demo(RSASignaturePadding pad, string name)
        {
            rsa ??= RSA.Create(2048); var data = Encoding.UTF8.GetBytes(inp.Text); var set = new HashSet<string>(); var sb = new StringBuilder($"-- {name}: ký 3 lần cùng dữ liệu, cùng private key --\r\n");
            for (int i = 1; i <= 3; i++)
            {
                var s = rsa.SignData(data, HashAlgorithmName.SHA256, pad); set.Add(Convert.ToBase64String(s));
                sb.Append($"Lần {i}: {Convert.ToBase64String(s)[..64]}...  verify={rsa.VerifyData(data, s, HashAlgorithmName.SHA256, pad)}\r\n");
            }
            return sb + $"=> Có {set.Count}/3 chữ ký khác nhau.";
        }
        Btn(bar, "Ký 3 lần - PKCS#1 v1.5 (tất định)", log, async () => Demo(RSASignaturePadding.Pkcs1, "PKCS#1 v1.5"));
        Btn(bar, "Ký 3 lần - RSASSA-PSS (salt ngẫu nhiên)", log, async () => Demo(RSASignaturePadding.Pss, "RSASSA-PSS"));
    }
}
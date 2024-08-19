import ssl
import datetime
import argparse
import warnings
import requests
import re
import socket
import base64
from cryptography import x509

warnings.filterwarnings("ignore")

KIRMIZI = "\033[91m"
SARI = "\033[93m"
ACI_YESIL = "\033[92;1m"
ACI_MAVI = "\033[96m"
RESET = "\033[0m"

KULLANICI_AGENTI = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def yazdir(stdout, dosyaGosterici=None, renk=None):
    if renk:
        print(f"{renk}{stdout}{RESET}")
    else:
        print(stdout)

    if dosyaGosterici is not None:
        dosyaGosterici.write(stdout + "\n")

def sertifikaAl(endpoint, dosyaGosterici):
    try:
        sertifika: bytes = ssl.get_server_certificate((endpoint, 443)).encode('utf-8')
        x509Sertifika = x509.load_pem_x509_certificate(sertifika)
    except Exception as e:
        yazdir(f"{KIRMIZI}[!] {endpoint} alınamadı: {e}{RESET}", dosyaGosterici)
        exit()
    
    yazdir(f"<<<<----- {endpoint} Sertifikası Analiz Ediliyor ----->>>>", dosyaGosterici, SARI)
    return x509Sertifika

def soketIleAl(endpoint, dosyaGosterici):
    yazdir(f"<<<<----- {endpoint} Sertifikası Analiz Ediliyor ----->>>>", dosyaGosterici, SARI)
    yazdir("[!] UYARI: Soket ile sertifika alınıyor", dosyaGosterici, SARI)
    hedef = (endpoint, 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect(hedef)
    except TimeoutError:
        return None

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=hedef[0])
    except:
        return None

    sertifika_bin = s.getpeercert(True)
    sertifikab64 = base64.b64encode(sertifika_bin).decode('ascii')

    s.shutdown(socket.SHUT_RDWR)
    s.close()

    pem_sertifika = "-----BEGIN CERTIFICATE-----\n"
    pem_sertifika += sertifikab64
    pem_sertifika += "\n-----END CERTIFICATE-----\n"

    sertifika_byteleri = pem_sertifika.encode('utf-8')
    x509Sertifika = x509.load_pem_x509_certificate(sertifika_byteleri)

    return x509Sertifika

def sertifikaBilgisiAl(x509Sertifika, dosyaGosterici):
    try:
        ortakAd = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except:
        yazdir("[!] Sertifika bilgisi alınamadı, lütfen alan adını kontrol edin veya www ekleyin.", dosyaGosterici, KIRMIZI)
        exit()

    try:
        organizasyonAdı = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        organizasyonAdı = "<Sertifikada Yer Almıyor>"

    try:    
        konuSeriNumarası = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
    except IndexError:
        konuSeriNumarası = "<Sertifikada Yer Almıyor>"
    
    try:
        ülkeAdı = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
    except IndexError:
        ülkeAdı = "<Sertifikada Yer Almıyor>"

    try:
        yerelAd = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
    except IndexError:
        yerelAd = "<Sertifikada Yer Almıyor>"
    
    try:
       İLEyalet = x509Sertifika.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
    except IndexError:
        İLEyalet = "<Sertifikada Yer Almıyor>"

    geçerlilikBaslangıcı = x509Sertifika.not_valid_before
    geçerlilikSonu = x509Sertifika.not_valid_after

    geçerlilik = True
    bugun = datetime.datetime.utcnow()

    if not geçerlilikBaslangıcı < bugun < geçerlilikSonu:
        geçerlilik = False
    
    sanUzantısı = x509Sertifika.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    sanAlanları = sanUzantısı.value.get_values_for_type(x509.DNSName)

    imzalayan = x509Sertifika.issuer
    ülke = imzalayan.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
    organizasyon = imzalayan.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    imzalayanCN = imzalayan.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    sertifikaBilgisi = {
        "OrtakAd": ortakAd,
        "Organizasyon": organizasyonAdı,
        "KonuSeri": konuSeriNumarası,
        "Ülke": ülkeAdı,
        "Yerel": yerelAd,
        "İLEyalet": İLEyalet,
        "Geçerlilik": geçerlilik,
        "İmzalayan": f"CN={imzalayanCN}, O={organizasyon}, C={ülke}",
        "SAN": sanAlanları
    }

    return sertifikaBilgisi

def sanÇıkar(endpoint, sanListesi, istekBayrağı, dosyaGosterici):
    benzersizUç noktalar = []

    for alan in sanListesi:
        geçerliAlan, temizAlan = alanıTemizle(endpoint, alan)
        if geçerliAlan:
            benzersizUç noktalar.append(temizAlan)
    
    sanBenzersiz = set(benzersizUç noktalar)
    yazdir(f"[+] SAN'dan {len(sanBenzersiz)} Alan alındı", dosyaGosterici, ACI_MAVI)

    for d in sanBenzersiz:
        if istekBayrağı:
            durum, başlık, urlŞeması = alanİste(d)
            if durum:
                if başlık:
                    yazdir(f"{d} [{urlŞeması}] [{durum}] [{başlık}]", dosyaGosterici)
                else:
                    yazdir(f"{d} [{urlŞeması}] [{durum}]", dosyaGosterici)
            else:
                yazdir(f"{d}", dosyaGosterici)
        else:
            yazdir(d, dosyaGosterici)
    return sanBenzersiz

def crtshSorgu(domain, istekBayrağı, dosyaGosterici):
    crtSonucu = True
    crtListesi = []

    try:
        r = requests.get(f"https://crt.sh/?q={domain.strip()}&output=json", headers={'User-Agent': KULLANICI_AGENTI})
        jsonSonuç = r.json()
    except Exception as e:
        crtSonucu = False
        yazdir(f"-----crt.sh'dan hata veya sonuç yok-----", dosyaGosterici, KIRMIZI)
        return crtListesi

    if r.status_code != 200:
        yazdir(f"-----crt.sh'dan hata yanıtı [durum: {r.status_code}]-----", dosyaGosterici, KIRMIZI)
        return crtListesi
    
    if crtSonucu:
        for sonuç in jsonSonuç:
            cAdı = sonuç["common_name"]

            if cAdı is not None:
                kapsamdaAlan, temizAlan = alanıTemizle(domain, cAdı)
                if kapsamdaAlan:
                    crtListesi.append(temizAlan)

            eşleşenKimlikler = sonuç["name_value"].strip().split("\n")

            if len(eşleşenKimlikler) > 0:
                for tekAlan in eşleşenKimlikler:
                    kapsamdaAlan, temizAlan = alanıTemizle(domain, tekAlan)
                    if kapsamdaAlan:
                        crtListesi.append(temizAlan)

    crtBenzersiz = set(crtListesi)
    yazdir(f"[+] crt.sh'dan {len(crtBenzersiz)} Alan alındı", dosyaGosterici, ACI_MAVI)

    for d in crtBenzersiz:
        if istekBayrağı:
            durum, başlık, urlŞeması = alanİste(d)
            if durum:
                if başlık:
                    yazdir(f"{d} [{urlŞeması}] [{durum}] [{başlık}]", dosyaGosterici)
                else:
                    yazdir(f"{d} [{urlŞeması}] [{durum}]", dosyaGosterici)
            else:
                yazdir(f"{d}", dosyaGosterici)
        else:
            yazdir(d, dosyaGosterici)

    return crtBenzersiz

def alanıTemizle(domain, testDomain):
    geçerliAlan = False
    if '*.' in testDomain:
        testDomain = testDomain.replace('*.', '')

    if f".{domain}" in testDomain:
        geçerliAlan = True

    if re.search(r'[^a-zA-Z0-9-.]', testDomain):
        geçerliAlan = False

    return geçerliAlan, testDomain

def alanİste(domain, zamanAşımı=2, urlŞeması="https"):
    başlık = None
    istekBaşarısız = False
    try:
        r = requests.get('https://' + domain.strip(), timeout=zamanAşımı, allow_redirects=True, verify=True, headers={'User-Agent': KULLANICI_AGENTI})
    except TimeoutError:
        istekBaşarısız = True
    except:
        istekBaşarısız = True
    
    if istekBaşarısız:
        try:
            r = requests.get('http://' + domain.strip(), timeout=zamanAşımı, allow_redirects=True, headers={'User-Agent': KULLANICI_AGENTI})
            urlŞeması = "http"
        except TimeoutError:
            return None, None, None
        except:
            return None, None, None
    
    başlıkAra = re.search(r'(?<=<title>).*(?=</title>)', r.text, re.IGNORECASE)
    if başlıkAra is not None:
        başlık = başlıkAra.group(0)

    return str(r.status_code), başlık, urlŞeması

def bannerSanatıYazdır():
    sanat = rf"""{ACI_MAVI} 
 ▄██████▄   ▄███████▄  ███▄▄▄▄    ▄█    █▄   ▄██████▄     ▄███████▄    ▄████████    ▄████████ 
███    ███ ██▀     ▄██ ███▀▀▀██▄ ███    ███ ███    ███   ███    ███   ███    ███   ███    ███ 
███    ███       ▄███▀ ███   ███ ███    ███ ███    ███   ███    ███   ███    █▀    ███    ███ 
███    ███  ▀█▀▄███▀▄▄ ███   ███ ███    ███ ███    ███   ███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
███    ███   ▄███▀   ▀ ███   ███ ███    ███ ███    ███ ▀█████████▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
███    ███ ▄███▀       ███   ███ ███    ███ ███    ███   ███          ███    █▄  ▀███████████ 
███    ███ ███▄     ▄█ ███   ███ ███    ███ ███    ███   ███          ███    ███   ███    ███ 
 ▀██████▀   ▀████████▀  ▀█   █▀   ▀██████▀   ▀██████▀   ▄████▀        ██████████   ███    ███ 
                                                                                   ███    ███ 
 v2.0{RESET}
    """
    print(sanat)

def ana():
    bannerSanatıYazdır()
   parser = argparse.ArgumentParser(prog='OZNvoper', 
                                     description='Türkiyenin En İyi Sub Domain Tarama Aleti.',
                                     usage='%(prog)s -e UÇ NOKTALAR')

    # Temel parametreler
    parser.add_argument("-d", "--domain", help="Taramak için uç noktalar, virgülle ayrılmış", required=False)
    parser.add_argument("-s", "--socket", help="Sertifika almak için kendi tanımlı soketi kullan", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("-i", "--input", help="Analiz edilecek alanları içeren giriş dosyası", required=False)
    parser.add_argument("-o", "--output", help="Sonuçları çıkartacak dosya", required=False)
    parser.add_argument("-c", "--certonly", help="Daha fazla sıralama olmadan yalnızca sertifika bilgisini göster", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("-r", "--request", help="GET isteği ile devam et", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("-l", "--log", help="Log dosyasına yaz", required=False)
    parser.add_argument("-t", "--timeout", type=int, default=2, help="İstek zaman aşımını belirle")
    parser.add_argument("-p", "--port", type=int, default=443, help="Hedef portu belirt")
    parser.add_argument("-v", "--verbose", help="Daha ayrıntılı çıktı için etkinleştir", action='store_true')
    parser.add_argument("-f", "--format", choices=['json', 'csv'], help="Çıktı formatı belirle", default='text')
    parser.add_argument("-a", "--analyze", help="Ek analiz seçeneklerini etkinleştir", action='store_true')

    # Ekstra parametreler
    parser.add_argument("-x", "--proxy", help="Proxy sunucusu kullanarak istek yapar", required=False)
    parser.add_argument("-e", "--exclude", help="Belirtilen alanları sonuçlardan hariç tutar", required=False)
    parser.add_argument("-n", "--no-verify", help="SSL sertifika doğrulamasını atlar", default=False, action='store_true')
    parser.add_argument("-m", "--method", choices=['GET', 'POST'], help="Kullanılacak HTTP metodunu belirt", default='GET')
    parser.add_argument("-h", "--headers", help="Özel HTTP başlıkları belirtmek için JSON formatında girdi", required=False)
    parser.add_argument("-q", "--quiet", help="Gürültüyü azaltmak için yalnızca kritik hataları göster", action='store_true')
    parser.add_argument("-z", "--retry", type=int, default=3, help="Başarısız istekler için tekrar deneme sayısı")
    parser.add_argument("-k", "--keep-alive", help="HTTP Keep-Alive bağlantısını etkinleştir", default=False, action='store_true')
    parser.add_argument("-j", "--json", help="JSON çıktısını etkinleştir", default=False, action='store_true')
    parser.add_argument("-u", "--user-agent", help="Özel User-Agent başlığı belirt", required=False)
    parser.add_argument("-b", "--body", help="POST isteği ile gönderilecek isteği gövdesi", required=False)

    # Daha fazla özel özellik
    parser.add_argument("-dL", "--debug-log", help="Hata ayıklama log dosyası belirt", required=False)
    parser.add_argument("-cL", "--config", help="Yapılandırma dosyası belirt", required=False)
    parser.add_argument("-fL", "--filter", help="Sonuçları filtrelemek için bir ifade belirt", required=False)
    parser.add_argument("-aL", "--alert", help="Belirtilen durumlar için uyarı gönder", required=False)
    parser.add_argument("-tL", "--test", help="Test modu etkinleştir", default=False, action='store_true')
    parser.add_argument("-nL", "--notification", help="Tamamlandığında bildirim gönder", action='store_true')

    # Ek parametreler
    parser.add_argument("-eL", "--email", help="Sonuçları e-posta ile gönder", required=False)
    parser.add_argument("-sl", "--silent", help="Hiçbir çıktı göstermeden çalışır", action='store_true')
    parser.add_argument("-bL", "--batch", help="Batched işlemler için dosya belirt", required=False)
    parser.add_argument("-g", "--gzip", help="Gzip sıkıştırması kullanarak sonuçları gönder", action='store_true')
    parser.add_argument("-cL", "--custom-headers", help="Özel başlıklar tanımlamak için bir dosya belirt", required=False)
    parser.add_argument("-iL", "--ignore-errors", help="Hataları göz ardı et", action='store_true')
    parser.add_argument("-pL", "--progress", help="İlerleme çubuğu göster", action='store_true')
    parser.add_argument("-tl", "--task-list", help="Yapılacak işlemler için bir liste belirt", required=False)
    parser.add_argument("-rL", "--response-time", help="Cevap süresini ölç", action='store_true')
    parser.add_argument("-dA", "--download", help="Belirtilen URL'den dosya indir", required=False)

    # Subdomain tarama için ek parametreler
    parser.add_argument("-sd", "--subdomain", help="Alt alan adlarını taramak için kullanılacak dosya", required=False)
    parser.add_argument("-sdv", "--subdomain-verbose", help="Alt alan adı taramasında daha ayrıntılı çıktı için etkinleştir", action='store_true')
    parser.add_argument("-sde", "--subdomain-exclude", help="Alt alan adları için hariç tutma listesi belirt", required=False)
    parser.add_argument("-sdt", "--subdomain-timeout", type=int, default=2, help="Alt alan adı taraması için zaman aşımını belirle")

    # Benzersiz özel parametreler
    parser.add_argument("--honeytoken", help="Bal küpü tokeni ekleyerek sahte istekleri tespit eder", action='store_true')
    parser.add_argument("--rate-limit", type=int, help="İstek başına hız sınırını belirle", default=10)
    parser.add_argument("--fingerprint", help="Cihaz parmak izi ile kimlik doğrulama yap", action='store_true')
    parser.add_argument("--captcha", help="İnsan doğrulaması için CAPTCHA kullan", action='store_true')
    parser.add_argument("--anomaly-detection", help="Anormal trafik tespiti için makine öğrenimi modelini kullan", action='store_true')
    parser.add_argument("--session-record", help="İstek oturumlarını kaydeder ve tekrar oynatır", action='store_true')
    parser.add_argument("--simulate", help="Gerçek tarama yerine simülasyon yapar", action='store_true')
    parser.add_argument("--dynamic-throttling", help="Dinamik hız sınırlandırma uygular", action='store_true')
    parser.add_argument("--geo-block", help="Belirli coğrafi konumlara göre istekleri engeller", action='store_true')
    parser.add_argument("--decoy", help="Yanıltıcı veri ile sahte sonuçlar üretir", action='store_true')
    parser.add_argument("--proxychains", help="ProxyChains kullanarak istek yapar", action='store_true')
    parser.add_argument("--rotate-proxies", help="İstekler için proxy listesini döndürerek kullanır", required=False)
    parser.add_argument("--dns-over-https", help="DNS sorgularını HTTPS üzerinden yapar", action='store_true')
    parser.add_argument("--stealth", help="Stealth modunu etkinleştirir, iz bırakmaz", action='store_true')
    parser.add_argument("--sandbox", help="Tüm işlemleri izole edilmiş bir sandbox ortamında çalıştırır", action='store_true')
    parser.add_argument("--auto-retry", help="Başarısız istekler için otomatik yeniden deneme mekanizması", action='store_true')
    parser.add_argument("--max-retries", type=int, default=5, help="Maksimum yeniden deneme sayısı")
    parser.add_argument("--config-file", help="Yapılandırma dosyasını belirt", required=False)
    parser.add_argument("--interactive-mode", help="Etkileşimli modda çalıştır", action='store_true')
    parser.add_argument("--visual-mode", help="Görsel arayüz modunda çalıştır", action='store_true')
    parser.add_argument("-dL", "--debug-log", help="Hata ayıklama log dosyası belirt", required=False)
    parser.add_argument("-cL", "--config", help="Yapılandırma dosyası belirt", required=False)
   parser.add_argument("-fL", "--filter", help="Sonuçları filtrelemek için bir ifade belirt", required=False)
   parser.add_argument("-aL", "--alert", help="Belirtilen durumlar için uyarı gönder", required=False)
   parser.add_argument("-tL", "--test", help="Test modu etkinleştir", action='store_true')
  parser.add_argument("-nL", "--notification", help="Tamamlandığında bildirim gönder", action='store_true')

# Ek Parametreler
parser.add_argument("-eL", "--email", help="Sonuçları e-posta ile gönder", required=False)
parser.add_argument("-sl", "--silent", help="Hiçbir çıktı göstermeden çalışır", action='store_true')
parser.add_argument("-bL", "--batch", help="Batched işlemler için dosya belirt", required=False)
parser.add_argument("-g", "--gzip", help="Gzip sıkıştırması kullanarak sonuçları gönder", action='store_true')
parser.add_argument("-cL", "--custom-headers", help="Özel başlıklar tanımlamak için bir dosya belirt", required=False)
parser.add_argument("-iL", "--ignore-errors", help="Hataları göz ardı et", action='store_true')
parser.add_argument("-pL", "--progress", help="İlerleme çubuğu göster", action='store_true')
parser.add_argument("-tl", "--task-list", help="Yapılacak işlemler için bir liste belirt", required=False)
parser.add_argument("-rL", "--response-time", help="Cevap süresini ölç", action='store_true')
parser.add_argument("-dA", "--download", help="Belirtilen URL'den dosya indir", required=False)

# Subdomain Tarama için Ek Parametreler
parser.add_argument("-sd", "--subdomain", help="Alt alan adlarını taramak için kullanılacak dosya", required=False)
parser.add_argument("-sdv", "--subdomain-verbose", help="Alt alan adı taramasında daha ayrıntılı çıktı için etkinleştir", action='store_true')
parser.add_argument("-sde", "--subdomain-exclude", help="Alt alan adları için hariç tutma listesi belirt", required=False)
parser.add_argument("-sdt", "--subdomain-timeout", type=int, default=2, help="Alt alan adı taraması için zaman aşımını belirle")
parser.add_argument("-wL", "--wordlist", help="Subdomain taraması için kelime listesi belirt", required=True)
parser.add_argument("-mS", "--mode", choices=['bruteforce', 'dictionary'], default='dictionary', help="Subdomain tarama modu")
parser.add_argument("-mxR", "--max-recursion", type=int, default=2, help="Maksimum yineleme derinliği")
parser.add_argument("-rsv", "--resolve", help="Alt alan adlarını IP'lere çözümle", action='store_true')
parser.add_argument("-cf", "--cname-follow", help="CNAME kayıtlarını takip et", action='store_true')
parser.add_argument("-tt", "--target-time", type=int, default=300, help="Tarama için toplam hedef süre")
parser.add_argument("-dp", "--dns-providers", help="DNS çözümlemesi için kullanılacak DNS sağlayıcıları", required=False)

# Çıktı ve Raporlama
parser.add_argument("-rf", "--report-format", choices=['txt', 'json', 'csv', 'html'], default='txt', help="Tarama sonuçlarının formatı")
parser.add_argument("-rp", "--report-path", help="Tarama sonuçlarını kaydetmek için dosya yolu", required=False)
parser.add_argument("-oc", "--output-clean", help="Temiz bir çıktı için yalnızca aktif subdomain'leri listele", action='store_true')
parser.add_argument("-rs", "--result-summary", help="Tarama sonunda özet rapor oluştur", action='store_true')

# Ağ ve Zamanlama
parser.add_argument("-rt", "--retry-timeout", type=int, default=5, help="Başarısız istekler için yeniden deneme zaman aşımı")
parser.add_argument("-mR", "--max-retries", type=int, default=3, help="Başarısız DNS istekleri için maksimum deneme sayısı")
parser.add_argument("-tn", "--thread-number", type=int, default=10, help="Tarama için kullanılacak iş parçacığı sayısı")
parser.add_argument("-rl", "--rate-limit", type=int, default=100, help="Saniye başına maksimum istek sayısı")
parser.add_argument("-tr", "--time-range", help="Taramayı belirli bir zaman aralığında gerçekleştir", required=False)

# Gelişmiş Tarama Özellikleri
parser.add_argument("-dS", "--dnssec", help="DNSSEC destekli subdomain'leri belirler", action='store_true')
parser.add_argument("-wR", "--wildcard", help="Wildcard DNS kayıtlarını tespit eder", action='store_true')
parser.add_argument("-mxS", "--mx-records", help="MX kayıtlarını tespit ederek subdomain'leri bulur", action='store_true')
parser.add_argument("-srv", "--srv-records", help="SRV kayıtlarını kullanarak subdomain'leri bulur", action='store_true')
parser.add_argument("-txt", "--txt-records", help="TXT kayıtlarını kullanarak subdomain'leri bulur", action='store_true')
parser.add_argument("-sp", "--suppress-duplicates", help="Tekrarlanan subdomain sonuçlarını bastır", action='store_true')

# Otomatik İşlem ve İzleme
parser.add_argument("-wl", "--watch-list", help="Belirtilen subdomain'ler üzerinde değişiklikleri izler", required=False)
parser.add_argument("-si", "--schedule-interval", type=int, help="Belirli aralıklarla otomatik tarama yap", required=False)
parser.add_argument("-at", "--auto-trigger", help="Özel durumlarda otomatik tarama tetikle", required=False)

# Hata ve Sorun Giderme
parser.add_argument("-dt", "--debug", help="Hata ayıklama modunu etkinleştir", action='store_true')
parser.add_argument("-hl", "--hard-limit", type=int, default=10000, help="İşlem başına maksimum alt alan adı sınırı")
parser.add_argument("-ab", "--abort", help="Belirli bir hata durumunda işlemi iptal et", required=False)
parser.add_argument("-rt", "--retry-errors", help="Hatalı istekleri yeniden dene", action='store_true')

# Ek Parametreler
parser.add_argument("-ip", "--ip-address", help="Taranacak IP adreslerini belirt", required=False)
parser.add_argument("-dns", "--dns-server", help="Kullanılacak DNS sunucusunu belirt", required=False)
parser.add_argument("-ttl", "--time-to-live", type=int, help="DNS sorguları için TTL değeri belirt", default=60)
parser.add_argument("-res", "--resolver", help="Kullanılacak DNS çözümleyicisi belirt", required=False)
parser.add_argument("-ts", "--timestamp", help="Sonuçlara zaman damgası ekle", action='store_true')
parser.add_argument("-tpf", "--target-protocol", choices=['http', 'https'], help="Taramada kullanılacak protokolü belirt", default='https')
parser.add_argument("-rsf", "--resolve-first", help="Tarama öncesi IP çözümlemesini gerçekleştir", action='store_true')

# Güvenlik ve Kimlik Doğrulama
parser.add_argument("-auth", "--authentication", help="Kimlik doğrulama bilgilerini belirt", required=False)
parser.add_argument("-sec", "--security", choices=['low', 'medium', 'high'], help="Güvenlik seviyesini belirt", default='medium')
parser.add_argument("-enc", "--encryption", help="Şifreleme yöntemini belirt", required=False)
parser.add_argument("-cf", "--captcha-file", help="CAPTCHA doğrulaması için dosya belirt", required=False)
parser.add_argument("-otp", "--one-time-password", help="Tek kullanımlık şifre ile doğrulama yap", action='store_true')
parser.add_argument("-api", "--api-key", help="API anahtarı ile doğrulama yap", required=False)
parser.add_argument("-cert", "--certificate", help="SSL sertifikasını belirt", required=False)
parser.add_argument("-ca", "--certificate-authority", help="Kullanılacak sertifika otoritesini belirt", required=False)

# Ağ ve Zamanlama
parser.add_argument("-rc", "--retry-count", type=int, help="Maksimum yeniden deneme sayısını belirt", default=3)
parser.add_argument("-cw", "--connection-wait", type=int, help="Bağlantı bekleme süresini belirt", default=2)
parser.add_argument("-nw", "--network-wait", type=int, help="Ağ yanıt bekleme süresini belirt", default=5)
parser.add_argument("-rt", "--response-timeout", type=int, help="Yanıt zaman aşımını belirt", default=60)
parser.add_argument("-rwt", "--retry-wait-time", type=int, help="Yeniden denemeler arası bekleme süresini belirt", default=5)
parser.add_argument("-cp", "--connection-pool", help="Bağlantı havuzu kullan", action='store_true')

# Gelişmiş Tarama Özellikleri
parser.add_argument("-ai", "--ai-analysis", help="Yapay zeka ile tarama sonuçlarını analiz et", action='store_true')
parser.add_argument("-ml", "--machine-learning", help="Makine öğrenimi modelini belirt", required=False)
parser.add_argument("-di", "--deep-inspection", help="Derinlemesine tarama yap", action='store_true')
parser.add_argument("-an", "--anomaly", help="Anomalileri tespit et", action='store_true')
parser.add_argument("-sig", "--signature", help="İmzalı verilerle doğrulama yap", required=False)
parser.add_argument("-for", "--forensics", help="Adli analiz için veri topla", action='store_true')
parser.add_argument("-sm", "--scan-mode", choices=['fast', 'comprehensive'], help="Tarama modunu belirt", default='fast')

# Otomatik İşlem ve İzleme
parser.add_argument("-mc", "--monitor-changes", help="Alt alan adı değişikliklerini izle", action='store_true')
parser.add_argument("-lfs", "--log-file-size", type=int, help="Maksimum log dosyası boyutunu belirt", default=10)
parser.add_argument("-cr", "--change-report", help="Değişiklik raporu oluştur", action='store_true')
parser.add_argument("-uip", "--update-ip", help="IP adreslerini güncelle", action='store_true')
parser.add_argument("-lfp", "--log-file-path", help="Log dosyasının kaydedileceği yolu belirt", required=False)
parser.add_argument("-sn", "--snapshot", help="Tarama öncesi ve sonrası durumun anlık görüntüsünü al", action='store_true')

# Hata ve Sorun Giderme
parser.add_argument("-err", "--error-log", help="Hata log dosyasını belirt", required=False)
parser.add_argument("-erm", "--error-mode", choices=['ignore', 'strict'], help="Hata modunu belirt", default='ignore')
parser.add_argument("-lb", "--log-backup", help="Log dosyasının yedeğini al", action='store_true')
parser.add_argument("-mem", "--memory-usage", help="Bellek kullanımını izleme modunu etkinleştir", action='store_true')
parser.add_argument("-cpb", "--create-backup", help="İşlem öncesi yedek oluştur", action='store_true')

# Çıktı ve Raporlama
parser.add_argument("-xt", "--xml-output", help="Sonuçları XML formatında çıkart", action='store_true')
parser.add_argument("-md", "--markdown", help="Sonuçları Markdown formatında çıkart", action='store_true')
parser.add_argument("-df", "--detailed-format", help="Daha detaylı bir çıktı formatı kullan", action='store_true')
parser.add_argument("-pi", "--print-interval", type=int, help="Çıktı raporlama aralığını belirt", default=30)
parser.add_argument("-lp", "--log-path", help="Log dosyasının kaydedileceği dizini belirt", required=False)
parser.add_argument("-lg", "--log-level", choices=['INFO', 'DEBUG', 'ERROR'], help="Log seviyesi belirt", default='INFO')
parser.add_argument("-eml", "--email-report", help="Raporu e-posta ile gönder", action='store_true')
parser.add_argument("-srt", "--sort-results", help="Sonuçları belirli bir kritere göre sırala", required=False)
parser.add_argument("-mr", "--merge-reports", help="Birden fazla raporu birleştir", action='store_true')

# Performans ve Kaynak Yönetimi
parser.add_argument("-prf", "--performance", help="Performans izleme modunu etkinleştir", action='store_true')
parser.add_argument("-rsc", "--resource-control", help="Kaynak kullanımını kontrol et", action='store_true')
parser.add_argument("-thr", "--thread-limit", type=int, help="İş parçacığı sınırını belirt", default=50)
parser.add_argument("-buf", "--buffer-size", type=int, help="Veri tampon boyutunu belirt", default=8192)
parser.add_argument("-rm", "--resource-monitor", help="Kaynak izleme modunu etkinleştir", action='store_true')

# Güvenlik ve Kimlik Doğrulama (Ek)
parser.add_argument("-twf", "--two-factor", help="İki aşamalı doğrulama kullan", action='store_true')
parser.add_argument("-mtk", "--mtls-key", help="Karşılıklı TLS için anahtar dosyasını belirt", required=False)
parser.add_argument("-mtc", "--mtls-cert", help="Karşılıklı TLS için sertifika dosyasını belirt", required=False)
parser.add_argument("-vpn", "--vpn-config", help="VPN yapılandırma dosyasını belirt", required=False)

    args = parser.parse_args()
    girişDosyası = args.input
    çıkışDosyası = args.output
    istekBayrağı = args.request
    sertifikaSadeceBayrağı = args.certonly
    alanDizesi = args.domain
    logDosyası = args.log

    dosyaGosterici = None
    logGosterici = None

    if çıkışDosyası:
        dosyaGosterici = open(çıkışDosyası, 'w')

    if logDosyası:
        logGosterici = open(logDosyası, 'a')  # Append mode

    if alanDizesi:
        uçNoktalar = alanDizesi.replace(" ", "").split(",")

    if girişDosyası:
        uçNoktalar = []
        try:
            with open(girişDosyası, 'r') as inFile:
                for alanlar in inFile:
                    uçNoktalar.append(alanlar.strip())
        except FileNotFoundError:
            print(f"{KIRMIZI}[!] Hata: Giriş dosyası mevcut değil{RESET}")
            exit()

    if alanDizesi is None and girişDosyası is None:
        print(f"{KIRMIZI}[!] Hata: -e veya -i ile belirtilen uç noktalar yok{RESET}")
        exit()

    for endpoint in uçNoktalar:
        if 'http://' in endpoint:
            print(f"{KIRMIZI}[!] http:// şeması dahil, kaldırılıyor...{RESET}") 
            endpoint = endpoint.lstrip('http://')
        elif 'https://' in endpoint:
            print(f"{KIRMIZI}[!] https:// şeması dahil, kaldırılıyor...{RESET}")
            endpoint = endpoint.lstrip('https://')

        if not args.socket:
            ayrıştırılanSertifika = sertifikaAl(endpoint, dosyaGosterici)
        else:
            ayrıştırılanSertifika = soketIleAl(endpoint, dosyaGosterici)

        sertifikaBilgisi = sertifikaBilgisiAl(ayrıştırılanSertifika, dosyaGosterici)

        for alanAnahtarı in sertifikaBilgisi:
            if alanAnahtarı != "SAN":
                yazdir(f"-> {alanAnahtarı}: {sertifikaBilgisi[alanAnahtarı]}", dosyaGosterici)

        if sertifikaSadeceBayrağı:
            yazdir(f"-> SAN DNS Adı(ları): {sertifikaBilgisi['SAN']}", dosyaGosterici)
            continue

        sanBenzersiz = sanÇıkar(endpoint, sertifikaBilgisi["SAN"], istekBayrağı, dosyaGosterici)
        crtBenzersiz = crtshSorgu(endpoint, istekBayrağı, dosyaGosterici)

        if len(sanBenzersiz) != 0 and len(crtBenzersiz) != 0:
            birleşikAlanlar = (sanBenzersiz).union(crtBenzersiz)
            yazdir(f"----- Toplam {endpoint} alanları keşfedildi: {len(birleşikAlanlar)} -----", dosyaGosterici, ACI_YESIL)
        elif len(sanBenzersiz) != 0:
            yazdir(f"----- Toplam {endpoint} alanları keşfedildi: {len(sanBenzersiz)} -----", dosyaGosterici, ACI_YESIL)
        elif len(crtBenzersiz) != 0:
            yazdir(f"----- Toplam {endpoint} alanları keşfedildi: {len(crtBenzersiz)} -----", dosyaGosterici, ACI_YESIL)
        else:
            yazdir(f"----- {endpoint} alanları keşfedilemedi -----", dosyaGosterici, KIRMIZI)

        # Log dosyasına yaz
        if logGosterici:
            logGosterici.write(f"{datetime.datetime.now()}: {endpoint} için keşfedilen alanlar: {len(sanBenzersiz) + len(crtBenzersiz)}\n")
    if çıkışDosyası:
        dosyaGosterici.close()
    if logDosyası:
        logGosterici.close()
if __name__ == '__main__':
    ana()

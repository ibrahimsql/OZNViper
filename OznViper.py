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

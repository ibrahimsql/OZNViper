# OZNViper

![OZNViper Logo](link_to_logo_image) <!-- Logo linkini buraya ekleyin -->

## Genel Bakış

OZNViper, SSL sertifikalarını analiz etmek ve kontrol etmek için geliştirilmiş bir araçtır. İnternet üzerindeki birçok hizmet, güvenli bağlantılar sağlamak için SSL sertifikaları kullanır. Bu araç, belirli bir alan adı için sertifika bilgilerini toplar ve alternatif adları (Subject Alternative Names - SAN) kontrol ederek güvenlik durumunu değerlendirir.

## Neden OZNViper?

Günümüzde siber güvenlik tehditleri artmakta ve SSL sertifikalarının güvenliği her zamankinden daha önemli hale gelmektedir. OZNViper, kullanıcıların alan adları için SSL sertifikalarını hızlı ve etkili bir şekilde kontrol etmelerine olanak tanır. Bu sayede, potansiyel güvenlik açıklarını önceden tespit edebilir ve gerekli önlemleri alabilirsiniz.

## Özellikler

- **SSL Sertifikası Analizi:** Sertifika bilgilerini detaylı bir şekilde görüntüler ve kullanıcıya sunar.
- **Alternatif Ad (SAN) Kontrolü:** Sertifikanın alternatif adlarını kontrol ederek, alan adının güvenliğini değerlendirir.
- **Geçerlilik Tarihleri:** Sertifikanın ne zaman sona ereceğini gösterir; bu sayede zamanında yenileme yapabilirsiniz.
- **İmzalayan Bilgileri:** Sertifikanın hangi otorite tarafından imzalandığını belirtir; bu da güvenilirliği değerlendirmenize yardımcı olur.
- **Kullanıcı Dostu Arayüz:** Basit ve anlaşılır bir komut satırı arayüzü ile kullanıcı deneyimini geliştirir.
- **Hızlı ve Etkili:** Sertifika bilgilerini hızlı bir şekilde toplar ve analiz eder.


# Kullanım (USAGE)

### Bayraklar (FLAGS):
-h, --help
Yardım mesajını gösterir ve çıkış yapar.
-d, --domain
Tarama yapılacak alan adlarını belirtir; birden fazla alan adı için virgülle ayırın.
-s, --socket
Ham soket ile SSL bağlantısını etkinleştirir (Varsayılan: False).
-i, --input
Alan adlarını içeren satırlardan oluşan bir girdi dosyasını belirtir.
-o, --output
Sonuçları kaydetmek için kullanılacak dosya adını belirtir.
-c, --certonly
Daha fazla ayrıntı olmadan yalnızca sertifika bilgilerini gösterir (Varsayılan: False).
-r, --request
Web'in canlı olup olmadığını kontrol etmek için GET isteği ile devam eder (Varsayılan: False).
-a, --all
Tüm HTTPS alan adlarını tarar (Yakında gelecek).

## Katkıda Bulunma
### Katkıda bulunmak isterseniz, lütfen aşağıdaki adımları izleyin:

Depoyu fork edin.
Yeni bir dal oluşturun (git checkout -b feature/YourFeature).
Değişikliklerinizi yapın ve commit edin (git commit -m 'Add new feature').
Dalınızı GitHub'a yükleyin (git push origin feature/YourFeature).
Bir pull request oluşturun.

## Gereksinimler

OZNViper'ı kullanmak için aşağıdaki gereksinimlerin karşılandığından emin olun:

- **Python 3.6 veya üzeri:** Python yüklü değilse, [Python'un resmi web sitesinden](https://www.python.org/downloads/) indirip yükleyebilirsiniz.
- **Gerekli kütüphaneler:** Proje ile birlikte gelen `requirements.txt` dosyasında belirtilmiştir.

## Kurulum

1. **Depoyu klonlayın:**

   ```bash
   git clone https://github.com/kullaniciadi/OZNViper.git
   cd OZNViper

# Gerekli kütüphaneleri yükleyin:
**Aşağıdaki komut ile gerekli kütüphaneleri yükleyebilirsiniz:**

pip install -r requirements.txt

## Aracı çalıştırın:

## Örnek Kullanım Komutları

1. **Tam enumerasyon ile SAN uzantısı, sertifika şeffaflık günlükleri (crt.sh) ve web'in canlı olup olmadığını kontrol etme (Tavsiye Edilir):**


#### Sessiz enumerasyon ile SAN uzantısı, sertifika şeffaflık günlükleri (Sadece sertifikayı almak için 1 istek gönderir):
   python3 oznviper.py -d example.com -r

python3 oznviper.py -d example.com
#### Yalnızca sertifika bilgilerini ve SAN uzantısı alanlarını alma:

#### python3 oznviper.py -d example.com -c
Birden fazla alan adını aynı anda tarama:


#### python3 oznviper.py -d "example.com, example2.com"
veya 
#### python3 oznviper.py -i input.txt
SSL kütüphanesi olmadan ham soket modunda çalıştırma:
python3 oznviper.py -d example.com -s
#### Sonuçları bir dosyaya kaydetme:
python3 oznviper.py -d example.com -o output.txt

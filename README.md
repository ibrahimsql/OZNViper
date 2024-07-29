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

## Gereksinimler

OZNViper'ı kullanmak için aşağıdaki gereksinimlerin karşılandığından emin olun:

- **Python 3.6 veya üzeri:** Python yüklü değilse, [Python'un resmi web sitesinden](https://www.python.org/downloads/) indirip yükleyebilirsiniz.
- **Gerekli kütüphaneler:** Proje ile birlikte gelen `requirements.txt` dosyasında belirtilmiştir.

## Kurulum

1. **Depoyu klonlayın:**

   ```bash
   git clone https://github.com/kullaniciadi/OZNViper.git
   cd OZNViper

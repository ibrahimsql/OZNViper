# 🌐 OZNViper

OZNViper, hedef alan adları üzerinde kapsamlı analizler yapmanıza ve SSL/TLS sertifikalarıyla ilgili bilgileri toplamanıza olanak tanıyan güçlü bir araçtır. İnternet güvenliği ve bilgi toplama süreçlerinizi kolaylaştırmak için tasarlandı.

## 📈 Özellikler

- **Sertifika Bilgisi Toplama**: Hedef alanların SSL/TLS sertifikalarını detaylı bir şekilde analiz edin.
- **HTTP İstek Metodları**: GET veya POST istekleriyle esnek veri alma seçenekleri.
- **Proxy Desteği**: İsteklerinizi bir proxy sunucusu aracılığıyla yönlendirin.
- **Çıktı Formatları**: Sonuçları JSON veya CSV formatında kaydedin.
- **Hata Ayıklama**: Hata ayıklama log dosyası oluşturun.
- **Özelleştirilmiş HTTP Başlıkları**: İsteklerinizde özel HTTP başlıkları kullanın.
- **SSL Doğrulama İptali**: SSL sertifika doğrulamasını atlayarak hız kazanın.
- **E-posta Bildirimleri**: Analiz sonuçlarını e-posta ile alın.

## 🛠️ Gereksinimler

- Python 3.x
- Gerekli kütüphaneler (örneğin, `requests`, `argparse`)

## 🚀 Kurulum

1. Depoyu klonlayın:
   ```bash
   git clone https://github.com/ibrahimsql/OZNViper.git
   cd OZNViper
2. Gerekli kütüphaneleri yükleyin:
   ```bash
pip install -r requirements.txt
## 📋 Parametreler
### Parametre	Açıklama
-d, --domain	Taramak için alan adları (zorunlu değil)
-s, --socket	Kendi tanımlı soketi kullan (varsayılan: False)
-i, --input	Giriş dosyası (zorunlu değil)
-o, --output	Sonuç dosyası (zorunlu değil)
-c, --certonly	Sadece sertifika bilgisi göster (varsayılan: False)
-r, --request	GET isteği ile devam et (varsayılan: False)
-l, --log	Log dosyasına yaz (zorunlu değil)
-t, --timeout	İstek zaman aşımı (varsayılan: 2)
-p, --port	Hedef portu (varsayılan: 443)
-v, --verbose	Ayrıntılı çıktı için etkinleştir
-f, --format	Çıktı formatı (varsayılan: text)
-a, --analyze	Ek analiz seçeneklerini etkinleştir
-x, --proxy	Proxy sunucusu kullanarak istek yap (zorunlu değil)
-e, --exclude	Hariç tutulacak alanlar (zorunlu değil)
-n, --no-verify	SSL doğrulamasını atla (varsayılan: False)
-m, --method	HTTP metodunu belirt (varsayılan: GET)
-h, --headers	Özel HTTP başlıkları (zorunlu değil)
-q, --quiet	Sadece kritik hataları göster
-z, --retry	Yeniden deneme sayısı (varsayılan: 3)
-k, --keep-alive	HTTP Keep-Alive bağlantısını etkinleştir
-j, --json	JSON çıktısını etkinleştir
-u, --user-agent	Özel User-Agent belirt (zorunlu değil)
-b, --body	POST isteği gövdesi (zorunlu değil)
-dL, --debug-log	Hata ayıklama log dosyası (zorunlu değil)
-cL, --config	Yapılandırma dosyası (zorunlu değil)
-fL, --filter	Sonuç filtreleme ifadesi (zorunlu değil)
-aL, --alert	Uyarı gönder (zorunlu değil)
-tL, --test	Test modu (varsayılan: False)
-nL, --notification	Tamamlandığında bildirim gönder
-eL, --email	Sonuçları e-posta ile gönder (zorunlu değil)
-sl, --silent	Hiç çıktı göstermeden çalışır
-bL, --batch	Batch işlemler için dosya (zorunlu değil)
-g, --gzip	Gzip sıkıştırması kullanarak sonuçları gönder
-cL, --custom-headers	Özel başlıklar için dosya (zorunlu değil)
-iL, --ignore-errors	Hataları göz ardı et
-pL, --progress	İlerleme çubuğunu göster
-tl, --task-list	Yapılacak işlemler için liste (zorunlu değil)
-rL, --response-time	Cevap süresini ölç
-dA, --download	URL'den dosya indir (zorunlu değil)

## 🤝 Katkıda Bulunma
Bu projeye katkıda bulunmak için lütfen bir dal oluşturun ve değişikliklerinizi pull isteği ile gönderin. Katkılarınızı dört gözle bekliyoruz!

## 📚 Örnek Kullanımlar

### 1. Temel Kullanım

Sertifika bilgilerini toplamak için belirli bir alan adını taramak:
python OZNViper.py -d example.com

### 2. Çıktıyı Dosyaya Kaydetme

Sertifika bilgilerini JSON formatında bir dosyaya kaydetmek için:
python OZNViper.py -d example.com -o result.json -f json

### 3. Giriş Dosyasından Alanlar

Bir dosyadan alan adlarını okuyarak tarama yapmak
python OZNViper.py -i domains.txt -o result.csv -f csv

### 4. Proxy Kullanımı

Bir proxy sunucusu üzerinden istek yapmak:
python OZNViper.py -d example.com -x http://proxy.example.com:8080

### 5. SSL Doğrulamasını Atlamak

SSL sertifika doğrulamasını atlayarak tarama yapmak:
python OZNViper.py -d example.com -n

### 6. Özel HTTP Başlıkları

Özel HTTP başlıkları kullanarak tarama yapmak:
python OZNViper.py -d example.com -h '{"Authorization": "Bearer token"}'

### 7. Zaman Aşımı Ayarı

İstek zaman aşımını 5 saniye olarak ayarlamak(örnek olarak 5):
python OZNViper.py -d example.com -t 5

### 8. Hata Ayıklama Modu

Hata ayıklama log dosyasını belirtmek:
python OZNViper.py -d example.com -dL debug.log

### 9. E-posta Bildirimi

Sonuçları belirtilen bir e-posta adresine göndermek:
python OZNViper.py -d example.com -e example@example.com


### 10. Çoklu Alan Adları ile Tarama

Birden fazla alan adını virgülle ayrılmış şekilde taramak:
python OZNViper.py -d example.com,another-example.com


### 11. HTTP Metodunu Belirleme

POST isteği ile tarama yapmak:
python OZNViper.py -d example.com -m POST


### 12. Yeniden Deneme Ayarı

Başarısız istekler için 5 kez yeniden denemek:
python OZNViper.py -d example.com -z 5


### 13. Hızlı Çalışma Modu

Hiçbir çıktı göstermeden çalışmak:
python OZNViper.py -d example.com -sl

### 14. Tüm Parametrelerle Kullanım

Tüm parametreleri kullanarak tarama yapmak:
python OZNViper.py -d example.com -i input.txt -o output.json -t 10 -n -m GET -v -z 3






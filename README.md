# DomainWatch

GitHub hesabı başına ayrı takip listesi ve Slack ayarları olan bir alan adı ve HTTPS sertifikası takip uygulaması. React ve Tailwind arayüzü, Hono API, D1 ve Cron aynı Cloudflare Worker dağıtımında çalışır. Canlı TLS sertifikası kontrolü için ayrıca küçük bir Node tarayıcısı çalıştırılır.

## Yerelde çalıştırma

Node.js 22.13+ ve npm gerekir.

```sh
npm ci
cp .dev.vars.example .dev.vars
openssl rand -base64 32
```

GitHub **Settings → Developer settings → OAuth Apps** altında bir uygulama oluşturun. Homepage URL için `http://localhost:8787`, Authorization callback URL için `http://localhost:8787/auth/github/callback` kullanın. İstemci kimliği ve secret değerlerini `.dev.vars` dosyasına yazın. OpenSSL çıktısını `WEBHOOK_KEY` olarak ekleyin. Tarayıcıdan `localhost` adresini kullanın. OAuth callback adresi ve `APP_ORIGIN` birebir eşleşmelidir.

```sh
npx wrangler d1 migrations apply domainwatch --local
npm run dev
```

Bir adres ekledikten sonra yerel cron çalıştırmak için:

```sh
curl -fsS 'http://localhost:8787/cdn-cgi/local/scheduled?format=json&cron=*/5+*+*+*+*'
```

### Canlı HTTPS sertifikası

Workers Static Assets ile sunulan panelde **TLS tarayıcısı bağlı değil** durumu, TLS adaptörünün yapılandırılmasını bekler. `poc/index.mjs` ile yapılan yerel Wrangler denemesinde `example.com:443` TLS bağlantısındaki `TLSSocket.getPeerCertificate()` çağrısı `Error: getPeerCertificate is not implemented` döndürdü. Yeniden üretmek için `npm run poc:tls` komutundan sonra `curl http://localhost:8788/` çalıştırın. [Cloudflare node:tls belgeleri](https://developers.cloudflare.com/workers/runtime-apis/nodejs/tls/)

Tarayıcı, host adının A kaydını çözer, genel IPv4 adresini filtreler ve DNS'i ikinci kez çözmeden o IP'nin 443 portuna özgün host adıyla SNI üzerinden bağlanır. Sunucunun sunduğu leaf sertifikanın `notAfter` alanını okur. Zincir veya hostname doğrulaması başarısız olsa da okunabilen tarih **Sertifika güvenilir değil** uyarısıyla gösterilir. IPv6-only adresler bu sürümde desteklenmez. CDN'in tarayıcıya sunduğu sertifika konuma ve TLS istemcisine göre değişebilir.

```sh
openssl rand -hex 32
# Üretilen değeri yerel süreç ortamına SCANNER_TOKEN olarak verin.
npm run scanner
```

Worker'ın `.dev.vars` dosyasına aynı `SCANNER_TOKEN` değerini ve `SCANNER_URL=http://127.0.0.1:9090/check` satırını ekleyip Worker'ı yeniden başlatın. Canlıda Node sürecini ağ erişimi olan ayrı bir makinede veya platformda çalıştırın. `npm ci --omit=dev` ve `npm run scanner` yeterlidir. Varsayılan olarak 127.0.0.1:9090 dinler. HTTPS reverse proxy'nin `POST /check` uç noktasını tarayıcıya yönlendirmesini sağlayın. Gerekirse `BIND_HOST` ve `PORT` ayarlayın. Tarayıcıyı özel ağlara erişimi olmayan bir ortamda çalıştırın ve egress'te özel/yerel ağlar ile platform metadata adreslerini engelleyin. TLS dışı bağlantı yalnız yerel geliştirmede etkin.

### Slack

**Ayarlar → Bildirim ayarları → Slack** alanına Slack'in verdiği `https://hooks.slack.com/services/…` adresini yapıştırın. Eşikleri seçin, bildirimleri etkinleştirin ve kaydedin. **Test mesajı gönder** kaydedilmiş adresle gerçek bir POST yapar ve otomatik bildirimler kapalıyken de çalışır. Test isteği kullanıcı başına sınırlandırılır. [Slack Incoming Webhooks](https://api.slack.com/incoming-webhooks)

Webhook URL'si D1'e AES-256-GCM ile ve kullanıcı kimliğine bağlı olarak şifreli yazılır. Ayar yanıtı sabit bir maske döndürür. Boş webhook alanıyla kaydetmek mevcut değeri korur. Anahtarı değiştirirseniz kullanıcıların webhook adreslerini yeniden kaydetmesi gerekir. Kimlik doğrulama GitHub OAuth state, PKCE ve D1'de hash olarak tutulan yedi günlük HTTP-only oturumla çalışır. Yazma istekleri aynı origin'den gelmelidir. [GitHub OAuth akışı](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)

## Cloudflare'a dağıtım

1. `npx wrangler login` ile doğru Cloudflare hesabına giriş yapın.
2. `npx wrangler d1 create domainwatch` çıktısındaki `database_id` değerini `wrangler.jsonc` içindeki örnek kimlikle değiştirin. Oradaki üç rate-limit namespace kimliği hesabınızda başka bir uygulamaya aitse benzersiz kimlikler verin.
3. Canlı GitHub OAuth App oluşturun. Homepage URL için Worker'ın HTTPS origin'ini, callback için aynı origin altında `/auth/github/callback` yolunu girin. Yerel OAuth App'i ayrı tutun.
4. Canlı TLS takibi için HTTPS tarayıcısını kurun. `SCANNER_URL` tam `/check` adresi, `SCANNER_TOKEN` tarayıcıyla ortak rastgele anahtar olmalı.
5. D1 migrasyonunu uygulayın ve Worker'ı dağıtın.

```sh
npx wrangler d1 migrations apply domainwatch --remote
npm run deploy
npx wrangler secret put APP_ORIGIN
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler secret put WEBHOOK_KEY
npx wrangler secret put SCANNER_URL
npx wrangler secret put SCANNER_TOKEN
```

`APP_ORIGIN` bir path veya sonda slash içermeyen HTTPS origin olmalıdır. Scanner secret'ları yalnız TLS tarayıcısı kullanılıyorsa gereklidir. Uygulamada test mesajı denemek için kullanıcıya ait geçerli bir Slack webhook adresi gerekir.

## Kontrol ve bildirim davranışı

- RDAP için Public Suffix List ile kayıt edilebilir alan adı bulunur. IANA'nın bootstrap listesi, TLD'nin HTTPS RDAP adreslerini belirler. İlk adres başarısızsa sıradaki denenir. `.com`, `.net` ve `.org` için kayıt operatörü adresleri ek fallback olarak tanımlıdır. RDAP desteği, kayıt bulunamaması, tarihin paylaşılmaması ve bağlantı hatası ayrı durumlar olarak görünür. [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json)
- Cron beş dakikada bir, süresi gelen iki adresi ve dört bildirimi işler. Her adresin bir sonraki kontrolü yaklaşık 24 saat sonra yapılır. MVP sınırı kullanıcı başına 25 ve toplam 400 adrestir. Yeni adresler sıraya girer. Trafik ve Cron CPU kullanımı gerçek dağıtımda gözlemlenmelidir. Tarayıcı barındırma maliyeti Cloudflare planına dahil değildir. [Workers limitleri](https://developers.cloudflare.com/workers/platform/limits/) · [D1 fiyatlandırması](https://developers.cloudflare.com/d1/platform/pricing/)
- 30/14/7/3/1 günlük pencerelerden en yakın seçili eşiğe bildirim yazılır. Örneğin ilk kontrolde 5 gün kaldıysa 7 günlük bildirim hazırlanır. D1'de adres, tarih türü, bitiş tarihi ve eşik kombinasyonu tekrar planlamayı önler.
- Ağ hataları, Slack 429 ve 5xx yanıtları artan bekleme süresiyle beş denemeye kadar yeniden denenir. Ayarı değişmiş veya güncel bitiş tarihi artık eşleşmeyen bekleyen bildirimler iptal edilir. Slack'in kabul ettiği isteğin yanıtı kaybolursa nadiren tekrar mesaj oluşabilir. Son teslim sonucu D1'de, denemeler yapılandırılmış Worker loglarında tutulur.
- Tenant sınırı tüm kullanıcı sorgularında uygulanır. Rate limit bağları Cloudflare lokasyonu başına çalışır. Webhook isteklerinde yönlendirme kapalıdır. TLS tarayıcısı hedef olarak yalnız genel IPv4 ve 443 portunu kullanır.

## Doğrulama

```sh
npm test
npm run typecheck
npm run build
npx wrangler deploy --dry-run
```

Otomatik testler tenant izolasyonu, webhook URL doğrulaması, şifreleme, maskeleme, Slack istek biçimi ve cron bildirim tekrarlarını denetler. Canlı GitHub girişi ve Slack mesajı için gerçek hesap yapılandırması gerekir.

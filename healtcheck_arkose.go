package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	mr "math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	listenPort := flag.String("port", "8080", "Port for the web server")
	targetURL := flag.String("url", "", "Target URL for the HTTP request")
	proxyURL := flag.String("proxy", "", "Proxy server URL")
	userAgent := flag.String("user-agent", "", "User Agent")
	serviceURL := flag.String("service-url", "", "${Service_URL}/fc/gt2/${Public_Key}")
	siteURL := flag.String("site-url", "", "post site data")
	publicKey := flag.String("public-key", "", "${Service_URL}/fc/gt2/${Public_Key}")
	capiVersion := flag.String("capi-version", "", "CAPI Version")
	capiPkey := flag.String("capi-pkey", "", "enforcement.${PKEY}.html")
	bda := flag.String("bda", "", "Browser data")

	flag.Parse()

	if *userAgent == "" {
		*userAgent = os.Getenv("USER_AGENT")
		if *userAgent == "" {
			*userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
		}
	}

	if *serviceURL == "" {
		*serviceURL = os.Getenv("SERVICE_URL")
		if *serviceURL == "" {
			*serviceURL = "https://tcr9i.chat.openai.com"
		}
	}

	if *siteURL == "" {
		*siteURL = os.Getenv("SITE_URL")
		if *siteURL == "" {
			*siteURL = "https://auth0.openai.com"
		}
	}

	if *publicKey == "" {
		*publicKey = os.Getenv("PUBLIC_KEY")
		if *publicKey == "" {
			*publicKey = "0A1D34FC-659D-4E23-B17B-694DCFCF6A6C"
		}
	}

	if *capiVersion == "" {
		*capiVersion = os.Getenv("CAPI_VERSION")
		if *capiVersion == "" {
			*capiVersion = "1.5.5"
		}
	}

	if *capiPkey == "" {
		*capiPkey = os.Getenv("CAPI_PKEY")
		if *capiPkey == "" {
			*capiPkey = "fbfc14b0d793c6ef8359e0e4b4a91f67"
		}
	}

	if *targetURL == "" || *proxyURL == "" {
		log.Fatal("Please provide both the target URL and the proxy URL")
	}

	if *publicKey == "" || *serviceURL == "" {
		log.Fatal("Please provide both the --publick-key and the --service-url")
	}

	_, err := url.ParseRequestURI(*targetURL)
	if err != nil {
		log.Fatal("Provided invalid target URL, it should include a schema (http:// or https://)")
	}

	_, err = url.ParseRequestURI(*proxyURL)
	if err != nil {
		log.Fatal("Provided invalid proxy URL, it should include a schema (http:// or https://)")
	}

	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1000000000)
	bx := fmt.Sprintf(`[{"key":"api_type","value":"js"},{"key":"p","value":1},{"key":"f","value":"9711bd3695defe0844fb8fd8a722f38b"},{"key":"n","value":"%s"},{"key":"wh","value":"80b13fd48b8da8e4157eeb6f9e9fbedb|5ab5738955e0611421b686bc95655ad0"},{"key":"enhanced_fp","value":[{"key":"webgl_extensions","value":null},{"key":"webgl_extensions_hash","value":null},{"key":"webgl_renderer","value":null},{"key":"webgl_vendor","value":null},{"key":"webgl_version","value":null},{"key":"webgl_shading_language_version","value":null},{"key":"webgl_aliased_line_width_range","value":null},{"key":"webgl_aliased_point_size_range","value":null},{"key":"webgl_antialiasing","value":null},{"key":"webgl_bits","value":null},{"key":"webgl_max_params","value":null},{"key":"webgl_max_viewport_dims","value":null},{"key":"webgl_unmasked_vendor","value":null},{"key":"webgl_unmasked_renderer","value":null},{"key":"webgl_vsf_params","value":null},{"key":"webgl_vsi_params","value":null},{"key":"webgl_fsf_params","value":null},{"key":"webgl_fsi_params","value":null},{"key":"webgl_hash_webgl","value":null},{"key":"user_agent_data_brands","value":null},{"key":"user_agent_data_mobile","value":null},{"key":"navigator_connection_downlink","value":null},{"key":"navigator_connection_downlink_max","value":null},{"key":"network_info_rtt","value":null},{"key":"network_info_save_data","value":null},{"key":"network_info_rtt_type","value":null},{"key":"screen_pixel_depth","value":24},{"key":"navigator_device_memory","value":null},{"key":"navigator_languages","value":"en-US,en"},{"key":"window_inner_width","value":0},{"key":"window_inner_height","value":0},{"key":"window_outer_width","value":0},{"key":"window_outer_height","value":0},{"key":"browser_detection_firefox","value":true},{"key":"browser_detection_brave","value":false},{"key":"audio_codecs","value":"{\"ogg\":\"probably\",\"mp3\":\"maybe\",\"wav\":\"probably\",\"m4a\":\"maybe\",\"aac\":\"maybe\"}"},{"key":"video_codecs","value":"{\"ogg\":\"probably\",\"h264\":\"probably\",\"webm\":\"probably\",\"mpeg4v\":\"\",\"mpeg4a\":\"\",\"theora\":\"\"}"},{"key":"media_query_dark_mode","value":false},{"key":"headless_browser_phantom","value":false},{"key":"headless_browser_selenium","value":false},{"key":"headless_browser_nightmare_js","value":false},{"key":"document__referrer","value":""},{"key":"window__ancestor_origins","value":null},{"key":"window__tree_index","value":[1]},{"key":"window__tree_structure","value":"[[],[]]"},{"key":"window__location_href","value":"https://tcr9i.chat.openai.com/v2/1.5.2/enforcement.64b3a4e29686f93d52816249ecbf9857.html#35536E1E-65B4-4D96-9D97-6ADB7EFF8147"},{"key":"client_config__sitedata_location_href","value":"https://chat.openai.com/"},{"key":"client_config__surl","value":"https://tcr9i.chat.openai.com"},{"key":"mobile_sdk__is_sdk"},{"key":"client_config__language","value":null},{"key":"audio_fingerprint","value":"35.73833402246237"}]},{"key":"fe","value":["DNT:1","L:en-US","D:24","PR:1","S:0,0","AS:false","TO:0","SS:true","LS:true","IDB:true","B:false","ODB:false","CPUC:unknown","PK:Linux x86_64","CFP:330110783","FR:false","FOS:false","FB:false","JSF:Arial,Arial Narrow,Bitstream Vera Sans Mono,Bookman Old Style,Century Schoolbook,Courier,Courier New,Helvetica,MS Gothic,MS PGothic,Palatino,Palatino Linotype,Times,Times New Roman","P:Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,PDF Viewer,WebKit built-in PDF","T:0,false,false","H:2","SWF:false"]},{"key":"ife_hash","value":"2a007a5daef41ee943d5fc73a0a8c312"},{"key":"cs","value":1},{"key":"jsbd","value":"{\"HL\":2,\"NCE\":true,\"DT\":\"\",\"NWD\":\"false\",\"DOTO\":1,\"DMTO\":1}"}]`,
		base64.StdEncoding.EncodeToString([]byte(timestamp)))
	// var bt = new Date() ['getTime']() / 1000
	bt := time.Now().UnixMicro() / 1000000
	// bw = Math.round(bt - (bt % 21600)
	bw := strconv.FormatInt(bt-(bt%21600), 10)
	bv := *userAgent

	if *bda == "" {
		encrypt := Encrypt(bx, bv+bw)
		encrypt = base64.StdEncoding.EncodeToString([]byte(encrypt))
		bda = &encrypt
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		var res Response
		response := postRequest(*serviceURL, *publicKey, *bda, *userAgent, *proxyURL, *capiVersion, *capiPkey, *siteURL)

		err := json.Unmarshal([]byte(response), &res)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error while making the request: ", err)
			return
		}

		if !strings.Contains(res.Token, "sup") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error Captcha is detected")
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, response)
		}
	})

	fmt.Printf("%-40s %s\n", "\033[1;34mPort for the web server:\033[0m", *listenPort)
	fmt.Printf("%-40s %s\n", "\033[1;34mProxy server URL:\033[0m", *proxyURL)
	fmt.Printf("%-40s %s\n", "\033[1;34mUser Agent:\033[0m", *userAgent)
	fmt.Printf("%-40s %s\n", "\033[1;34mService URL:\033[0m", *serviceURL)
	fmt.Printf("%-40s %s\n", "\033[1;34mPost site data:\033[0m", *siteURL)
	fmt.Printf("%-40s %s\n", "\033[1;34mPublic Key:\033[0m", *publicKey)
	fmt.Printf("%-40s %s\n", "\033[1;34mCAPI Version:\033[0m", *capiVersion)
	fmt.Printf("%-40s %s\n", "\033[1;34mCAPI PKEY:\033[0m", *capiPkey)

	log.Fatal(http.ListenAndServe(":"+*listenPort, mux))
}

type Response struct {
	Token string `json:"token"`
}

func postRequest(serviceURL string, publicKey string, bda string, userAgent string, proxies string, capiVersion string, capiPkey string, siteURL string) string {
	mr.Seed(time.Now().UnixNano())
	rnd := mr.Float64()

	urlParsed, _ := url.Parse(serviceURL)
	authority := urlParsed.Host

	publicUrl := fmt.Sprintf("%s/fc/gt2/public_key/%s", serviceURL, publicKey)
	data := url.Values{}
	data.Set("bda", bda)
	data.Set("public_key", publicKey)
	data.Set("site", siteURL)
	data.Set("userbrowser", userAgent)
	data.Set("capi_version", capiVersion)
	data.Set("capi_mode", "lightbox")
	data.Set("style_theme", "default")
	data.Set("simulate_rate_limit", "0")
	data.Set("simulated", "0")
	data.Set("rnd", strconv.FormatFloat(rnd, 'f', -1, 64))

	req, _ := http.NewRequest("POST", publicUrl, strings.NewReader(data.Encode()))
	req.Header.Add("authority", authority)
	req.Header.Add("accept", "*/*")
	req.Header.Add("accept-language", "en-US,en;q=0.9")
	req.Header.Add("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("origin", serviceURL)
	req.Header.Add("referer", fmt.Sprintf("%s/v2/%s/enforcement.%s.html", serviceURL, capiVersion, capiPkey))
	req.Header.Add("pragma", "no-cache")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("sec-ch-ua", `"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"`)
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", `"Linux"`)
	req.Header.Add("sec-fetch-dest", "empty")
	req.Header.Add("sec-fetch-mode", "cors")
	req.Header.Add("sec-fetch-site", "same-origin")

	if proxies != "" {
		proxyURL, _ := url.Parse(proxies)
		http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body)
}

type EncryptionData struct {
	Ct string `json:"ct"`
	Iv string `json:"iv"`
	S  string `json:"s"`
}

func Encrypt(data string, key string) string {
	encData, _ := AesEncrypt(data, key)

	encDataJson, err := json.Marshal(encData)
	if err != nil {
		panic(err)
	}

	return string(encDataJson)
}

func AesDecrypt(cipherText string, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	if string(data[:8]) != "Salted__" {
		return "", errors.New("invalid crypto js aes encryption")
	}

	salt := data[8:16]
	cipherBytes := data[16:]
	key, iv, err := DefaultEvpKDF([]byte(password), salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherBytes, cipherBytes)

	result := PKCS5UnPadding(cipherBytes)
	return string(result), nil
}

func AesEncrypt(content string, password string) (*EncryptionData, error) {
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	key, iv, err := DefaultEvpKDF([]byte(password), salt)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	cipherBytes := PKCS5Padding([]byte(content), aes.BlockSize)
	mode.CryptBlocks(cipherBytes, cipherBytes)

	//TODO: remove redundant code
	md5Hash := md5.New()
	salted := ""
	var dx []byte

	for i := 0; i < 3; i++ {
		md5Hash.Write(dx)
		md5Hash.Write([]byte(password))
		md5Hash.Write(salt)

		dx = md5Hash.Sum(nil)
		md5Hash.Reset()

		salted += hex.EncodeToString(dx)
	}

	cipherText := base64.StdEncoding.EncodeToString(cipherBytes)
	encData := &EncryptionData{
		Ct: cipherText,
		Iv: salted[64 : 64+32],
		S:  hex.EncodeToString(salt),
	}
	return encData, nil
}

// https://stackoverflow.com/questions/27677236/encryption-in-javascript-and-decryption-with-php/27678978#27678978
// https://github.com/brix/crypto-js/blob/8e6d15bf2e26d6ff0af5277df2604ca12b60a718/src/evpkdf.js#L55
func EvpKDF(password []byte, salt []byte, keySize int, iterations int, hashAlgorithm string) ([]byte, error) {
	var block []byte
	var hasher hash.Hash
	derivedKeyBytes := make([]byte, 0)
	switch hashAlgorithm {
	case "md5":
		hasher = md5.New()
	default:
		return []byte{}, errors.New("not implement hasher algorithm")
	}
	for len(derivedKeyBytes) < keySize*4 {
		if len(block) > 0 {
			hasher.Write(block)
		}
		hasher.Write(password)
		hasher.Write(salt)
		block = hasher.Sum([]byte{})
		hasher.Reset()

		for i := 1; i < iterations; i++ {
			hasher.Write(block)
			block = hasher.Sum([]byte{})
			hasher.Reset()
		}
		derivedKeyBytes = append(derivedKeyBytes, block...)
	}
	return derivedKeyBytes[:keySize*4], nil
}

func DefaultEvpKDF(password []byte, salt []byte) (key []byte, iv []byte, err error) {
	// https://github.com/brix/crypto-js/blob/8e6d15bf2e26d6ff0af5277df2604ca12b60a718/src/cipher-core.js#L775
	keySize := 256 / 32
	ivSize := 128 / 32
	derivedKeyBytes, err := EvpKDF(password, salt, keySize+ivSize, 1, "md5")
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return derivedKeyBytes[:keySize*4], derivedKeyBytes[keySize*4:], nil
}

// https://stackoverflow.com/questions/41579325/golang-how-do-i-decrypt-with-des-cbc-and-pkcs7
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "io/ioutil"

    "net/http"
    "os"
    "strings"
    "time"

    "github.com/spf13/cobra"
    "gopkg.in/square/go-jose.v2"
)

func writeKey(path string, k *ecdsa.PrivateKey) error {
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    bytes, err := x509.MarshalECPrivateKey(k)
    if err != nil {
        return err
    }
    b := &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}
    if err := pem.Encode(f, b); err != nil {
        f.Close()
        return err
    }
    return f.Close()
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if err != nil {
        return nil, err
    }
    key, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    return key, nil
}


type Directory struct {
    NewAccount string
    NewNonce string
    NewOrder string
}

func discover(url string) (*Directory, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("unexpected http status %s", resp.Status)
    }

    var js struct {
        NewAccount string `json:"newAccount"`
        NewNonce   string `json:"newNonce"`
        NewOrder   string `json:"newOrder"`
        RevokeCert string `json:"revokeCert"`
        Meta   struct {
            Terms   string   `json:"termsOfService"`
        }
    }
    decoder := json.NewDecoder(resp.Body)
    err = decoder.Decode(&js)
    if err != nil {
        return nil, err
    }
    fmt.Println("acme directory:")
    fmt.Printf("  newAccount: %s\n", js.NewAccount)
    fmt.Printf("  newNonce:   %s\n", js.NewNonce)
    fmt.Printf("  newOrder:   %s\n", js.NewOrder)
    return &Directory{
        NewAccount: js.NewAccount,
        NewNonce: js.NewNonce,
        NewOrder: js.NewOrder,
    }, nil
}

func getNonce(url string) string {
    resp, err := http.Get(url)
    if err != nil {
        panic(err)
    }
    resp.Body.Close()
    return resp.Header.Get("replay-nonce")
}

type Order struct {
    Status string
    Authorizations []string
    FinalizeUrl string
    OrderUrl string
    Certificate string
}


func parseOrderResponse2(resp *http.Response) (*Order, error) {
    orderLocation := resp.Header.Get("Location")
    fmt.Printf("order location %s\n", orderLocation)
    var js struct {
        Status string`json:"status"`
        Identifiers []struct {
            Type string `json:"type"`
            Value string `json:"value"`
        } `json:"Identifiers"`
        Authorizations []string `json:"authorizations"`
        Finalize string `json:"finalize"`
        Certificate string`json:"certificate"`
    }
    decoder := json.NewDecoder(resp.Body)
    err := decoder.Decode(&js)
    if err != nil {
        return nil, err
    }
    return &Order {
        Authorizations: js.Authorizations,
        FinalizeUrl: js.Finalize,
        OrderUrl: orderLocation,
        Status: js.Status,
        Certificate: js.Certificate,
    }, nil
}

type AuthChallenge struct {
    Type string
    Url string
    Token string
    Status string
}

func parseAuthz(resp *http.Response) *AuthChallenge {
    var js struct {
        Status string `json:"status"`
        Challenges []struct {
            Type  string `json:"type"`
            Url   string `json:"url"`
            Token string `json:"token"`
        } `json:"challenges"`
    }
    decoder := json.NewDecoder(resp.Body)
    err := decoder.Decode(&js)
    if err != nil {
        panic(err)
    }
    fmt.Println(js)
    for _, ch := range(js.Challenges) {
        if ch.Type == "http-01" {
            return &AuthChallenge{
                Type: ch.Type,
                Url: ch.Url,
                Token: ch.Token,
                Status: js.Status,
            }
        }
    }
    return nil
}

type NS struct {
    nonce string
}
func (ns NS)Nonce()(string, error) {
    return ns.nonce, nil
}

func postJWS(key *ecdsa.PrivateKey, url string, payload string, nonce string, kid string) *http.Response {
    jsonWebKey := jose.JSONWebKey{
        Key:       key,
        Algorithm: string(jose.ES256),
    }
    options := &jose.SignerOptions{}
    options.WithHeader("url", url)
    if len(kid) > 0 {
        options.WithHeader("kid", kid)
    } else {
        options.EmbedJWK = true
    }
    options.NonceSource = NS{nonce}


    signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jsonWebKey}, options)
    if err != nil {
        panic(err)
    }
    jws, err := signer.Sign([]byte(payload))
    if err != nil {
        fmt.Println(err.Error())
    }
    output := jws.FullSerialize()
    res, err := http.Post(url, "application/jose+json", strings.NewReader(output))
    return res
}

func thumb(key *ecdsa.PrivateKey) string {
    jsonWebKey := jose.JSONWebKey{
        Key:       key,
        //KeyID:     kid,
        Algorithm: string(jose.ES256),
    }

    pub := jsonWebKey.Public()
    th, _ := pub.Thumbprint(crypto.SHA256)
    return base64.RawURLEncoding.EncodeToString(th[:])
}

func createCSR(key *ecdsa.PrivateKey, host string) []byte {
    req := &x509.CertificateRequest {
        Subject: pkix.Name{CommonName: host},
        DNSNames: []string{host},
    }
    csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
    if err != nil {
        panic(err)
    }
    return csr
}

func handleGlobalFlags(cmd *cobra.Command) {
    insecure, _ := cmd.Flags().GetBool("insecure")
    if insecure {
        http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    }
}


func accCreate(cmd *cobra.Command, args []string) {
    handleGlobalFlags(cmd)
    authorityUrl, err := cmd.Flags().GetString("authority-url")
    if err != nil {
        panic(err)
    }
    fmt.Println("generating private key...")
    ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }
    writeKey("account-key.pem", ecKey)

    fmt.Println("discovering registry")
    directory, err := discover(authorityUrl)
    if err != nil {
        panic(err)
    }

    nonce := getNonce(directory.NewNonce)
    fmt.Printf("nonce=%s\n", nonce)

    // create new account
    fmt.Println("creating account")
    newAcc := `{"termsOfServiceAgreed":true,"contact":["mailto:adm1@admin.cz"]}`
    res := postJWS(ecKey, directory.NewAccount, newAcc, nonce, "")
    if (res == nil) || (res.StatusCode != 201) {
        fmt.Printf("account was not created %s\n", res.Status)
        return
    }

    account := res.Header.Get("Location")
    nonce = res.Header.Get("replay-nonce")
    body, err := ioutil.ReadAll(res.Body)
    if err == nil {
        fmt.Println(string(body))
    }
    res.Body.Close()

    fmt.Println(account)
    ioutil.WriteFile("account-name.txt", []byte(account), 0666)
}

func order(cmd *cobra.Command, args []string) {
    handleGlobalFlags(cmd)
    authorityUrl, err := cmd.Flags().GetString("authority-url")
    if err != nil {
        panic(err)
    }
    proofPort, err := cmd.Flags().GetString("proof-port")
    if err != nil {
        panic(err)
    }
    accountBytes, err := ioutil.ReadFile("account-name.txt")
    if err != nil{
        panic(err)
    }

    account := string(accountBytes)
    fmt.Printf("account:%s\n", account)
    ecKey, err := readKey("account-key.pem")
    if err != nil {
        panic(err)
    }

    hostname := args[0]
    fmt.Printf("order hostname %s\n", hostname)


    ecKeyCSR, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    writeKey("key-"+hostname+".pem", ecKeyCSR)

    csr := createCSR(ecKeyCSR, hostname)
    //fmt.Println(csr)

    fmt.Println("discovering registry")
    directory, err := discover(authorityUrl)
    if err != nil {
        panic(err)
    }

    nonce := getNonce(directory.NewNonce)
    fmt.Printf("nonce=%s\n", nonce)



    // start certificate order
    fmt.Println("issuing new order")
    //validNotAfter := time.Now().Add(24*time.Hour*30).Format(time.RFC3339)
    /*newOrder := fmt.Sprintf(`{"identifiers": [ { "type": "dns", "value": "%s" } ],"notAfter": "%s"}`,
                            hostname, validNotAfter)*/
    newOrder := fmt.Sprintf(`{"identifiers": [ { "type": "dns", "value": "%s" } ]}`,hostname)
    res := postJWS(ecKey, directory.NewOrder, newOrder, nonce, account)
    nonce = res.Header.Get("replay-nonce")
    if res.StatusCode == 400 {
        resp, _ := ioutil.ReadAll(res.Body)
        fmt.Println(string(resp))
    }
    order, err := parseOrderResponse2(res)
    if err != nil {
        panic(err)
    }
    res.Body.Close()
    fmt.Printf("order resp: %s\n", res.Status)
    fmt.Println(order)

    // start authorization
    fmt.Printf("issuing authorization %s\n", order.Authorizations[0])
    res = postJWS(ecKey, order.Authorizations[0], "", nonce, account)
    challenge := parseAuthz(res)
    nonce = res.Header.Get("replay-nonce")
    res.Body.Close()

    fmt.Println("starting http server")
    httpHandler := func (w http.ResponseWriter, r *http.Request) {
        if len(r.URL.Path) < 3 {
            w.WriteHeader(200)
            return
        }
        spl := strings.Split(r.URL.Path, "/")
        fmt.Printf("http got request %s\n", r.URL.Path)
        if (len(spl)<4) || (spl[1] != ".well-known") || (spl[2] != "acme-challenge") {
            fmt.Println("unexpected http request")
            return
        }
        w.Header().Add("Content-Type", "application/octet-stream")
        out := spl[3] + "." + thumb(ecKey)
        w.Write([]byte(out))
        fmt.Printf("http sending response %s\n", out)
    }

    httpServer := &http.Server{
        Addr:           ":"+proofPort,
        Handler:        http.HandlerFunc(httpHandler),
        ReadTimeout:    10 * time.Second,
        WriteTimeout:   10 * time.Second,
        MaxHeaderBytes: 1 << 20,
    }
    go func() {
        err := httpServer.ListenAndServe()
        if err != nil {
            fmt.Println(err)
        }
    }()
    for { // make sure our http server is up
        tstRsp, err := http.Get("http://localhost:"+proofPort)
        //fmt.Println(tstRsp)
        if (err == nil) && (tstRsp.StatusCode == 200) {
            break
        } else if err != nil {
            fmt.Println(err)
        } else {
            fmt.Println(tstRsp.Status)
        }
        time.Sleep(100*time.Millisecond)
    }

    fmt.Printf("confirm server is ready %s\n", challenge.Url)
    // confirm we arranged resource
    res = postJWS(ecKey, challenge.Url, "{}", nonce, account)
    nonce = res.Header.Get("replay-nonce")

    // give them time to perform authorization
    time.Sleep(100*time.Millisecond)

    // wait until autorized / status=valid
    for {
        res = postJWS(ecKey, order.Authorizations[0], "", nonce, account)
        nonce = res.Header.Get("replay-nonce")
        aresp := parseAuthz(res)
        status := aresp.Status
        fmt.Printf("auth url:%s status: %s\n", order.Authorizations[0], status)
        if (res.StatusCode == 200) && (status == "valid") {
            break
        }
        time.Sleep(1000 * time.Millisecond)
    }

    
    fmt.Println("send csr")
    csrReq := `{"csr":"`+ base64.RawURLEncoding.EncodeToString(csr[:])+`"}`
    fmt.Printf("csr requst: %s\n", csrReq)
    for {
        res = postJWS(ecKey, order.FinalizeUrl, csrReq, nonce, account)
        nonce = res.Header.Get("replay-nonce")
        if res.StatusCode == 200 {
            break
        }
        if res.StatusCode == 400 {
            b, _ := ioutil.ReadAll(res.Body)
            fmt.Println(string(b))
        }
        time.Sleep(1000 * time.Millisecond)
        fmt.Println(res)
    }

    fmt.Println("try to get cert")
    path := ""
    for {
        res = postJWS(ecKey, order.OrderUrl, "", nonce, account)
        nonce = res.Header.Get("replay-nonce")
        //path = parseOrderFinal(res)
        resporder, err := parseOrderResponse2(res)
        if err != nil {
            fmt.Println("problem getting cert %s", err.Error())
        } else {
            path = resporder.Certificate
            fmt.Printf("order response cerificate url:%s\n", path)
            if len(path) > 3 {
                break
            }
        }
        time.Sleep(1000 * time.Millisecond)
    }

    res = postJWS(ecKey, path, "", nonce, account)
    fmt.Printf("cert download status %s\n", res.Status)
    chainOut, _ := os.Create(fmt.Sprintf("chain-%s.pem", hostname))
    defer chainOut.Close()
    io.Copy(chainOut, res.Body)
}



func main() {

    var rootCmd = &cobra.Command{
        Use:   "acmec [command]",
        Short: "acme client",
    }
    rootCmd.PersistentFlags().StringP("authority-url", "u", "https://localhost:14000/dir", "authority url")
    rootCmd.PersistentFlags().StringP("proof-port", "p", "5002", "proof port")
    rootCmd.PersistentFlags().Bool("insecure", false, "insecure - do not verify server certificates")
    accountCreate := &cobra.Command {
        Use: "acc-create",
        Run: accCreate,
    }
    orderCommand := &cobra.Command {
        Use: "order [hostname]",
        Args: cobra.MinimumNArgs(1),
        Run: order,
    }

    rootCmd.AddCommand(accountCreate)
    rootCmd.AddCommand(orderCommand)
    rootCmd.Execute()
}

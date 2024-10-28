package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	requestURL  = "speed.cloudflare.com/cdn-cgi/trace"
	timeout     = 1 * time.Second
	maxDuration = 2 * time.Second
	batchSize   = 1000
)

var (
	asnList     = flag.String("asn", "", "ASN号码使用逗号分隔")
	defaultPort = flag.Int("port", 443, "端口")
	maxThreads  = flag.Int("max", 50, "最大并发请求数")
	enableTLS   = flag.Bool("tls", true, "启用 TLS")
)

type result struct {
	ip          string
	port        int
	dataCenter  string
	region      string
	city        string
	latency     string
	tcpDuration time.Duration
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

type CIDRBlock struct {
	Prefix string `json:"prefix"`
}

type ASNInfo struct {
	Name        string `json:"name"`
	CountryCode string `json:"country_code"`
}

func main() {
	flag.Parse()
	if *asnList == "" {
		fmt.Println("ASN编号")
		return
	}
	asns := strings.Split(*asnList, ",")

	for _, asn := range asns {
		asn := strings.TrimSpace(asn)
		if asn == "" {
			continue
		}

		clearConsole()
		startTime := time.Now()

		asnInfo, err := getASNInfo(asn)
		if err != nil {
			fmt.Printf("无法获取有关 ASN %s: %v\n", asn, err)
			continue
		}

		outFile := asnInfo.Name + ".csv"

		fmt.Printf("ASN 信息: %s\n", asn)
		fmt.Printf("  名字: %s\n", asnInfo.Name)
		fmt.Printf("  国家: %s\n", asnInfo.CountryCode)

		locations, err := loadLocations()
		if err != nil {
			fmt.Printf("无法加载位置: %v\n", err)
			continue
		}

		locationMap := createLocationMap(locations)

		if err := prepareOutputFile(outFile); err != nil {
			fmt.Printf("无法准备输出文件: %v\n", err)
			continue
		}

		validIPCount, err := processIPsFromASN(asn, locationMap, batchSize, outFile)
		if err != nil {
			fmt.Printf("无法处理IP地址 ASN %s: %v\n", asn, err)
			continue
		}

		elapsed := time.Since(startTime)
		if validIPCount == 0 {
			fmt.Printf("没有有效的ASN IP\n")
		} else {
			fmt.Printf("结果已成功写入 %s, 用时 %s\n", outFile, formatDuration(elapsed))
		}
	}
}

func getASNInfo(asn string) (ASNInfo, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s", asn)
	resp, err := http.Get(url)
	if err != nil {
		return ASNInfo{}, fmt.Errorf("无法获取有关 ASN: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ASNInfo{}, fmt.Errorf("无法获取ASN信息 : 收到状态码 %d", resp.StatusCode)
	}

	var response struct {
		Data ASNInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return ASNInfo{}, fmt.Errorf("无法解析答案: %v", err)
	}

	return response.Data, nil
}

func loadLocations() ([]location, error) {
	var locations []location

	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
        fmt.Println("本地文件 locations.json 未找到，正在加载...")
        resp, err := http.Get("https://speed.cloudflare.com/locations")
        if err != nil {
            return nil, fmt.Errorf("无法从 URL 获取 JSON: %v", err)
        }
        defer resp.Body.Close()

        if err := json.NewDecoder(resp.Body).Decode(&locations); err != nil {
            return nil, fmt.Errorf("无法解析 JSON: %v", err)
        }

        file, err := os.Create("locations.json")
        if err != nil {
            return nil, fmt.Errorf("无法创建文件: %v", err)
        }
        defer file.Close()

        if err := json.NewEncoder(file).Encode(locations); err != nil {
            return nil, fmt.Errorf("无法将 JSON 写入文件: %v", err)
        }
    } else {
        fmt.Println("本地文件 locations.json 已找到，正在加载...")
        file, err := os.Open("locations.json")
        if err != nil {
            return nil, fmt.Errorf("无法读取文件: %v", err)
        }
        defer file.Close()

        if err := json.NewDecoder(file).Decode(&locations); err != nil {
            return nil, fmt.Errorf("无法解析 JSON: %v", err)
        }
    }

	return locations, nil
}

func createLocationMap(locations []location) map[string]location {
	locationMap := make(map[string]location)
	for _, loc := range locations {
	    locationMap[loc.Iata] = loc
    }
	return locationMap
}

func prepareOutputFile(outFile string) error {
	if err := os.Remove(outFile); err != nil && !os.IsNotExist(err) {
	    return fmt.Errorf("无法删除现有文件: %v", err)
    }
	return nil
}

func processIPsFromASN(asn string, locationMap map[string]location, batchSize int, outFile string) (int, error) {
	fmt.Printf("正在处理 ASN: %s\n", asn)

	cidrBlocks, err := fetchCIDRBlocksFromASN(asn)
	if err != nil {
	    return 0, err
    }

	fmt.Printf("总共 CIDR 块: %d\n", len(cidrBlocks))

	totalIPs, err := calculateTotalIPs(cidrBlocks)
	if err != nil {
	    return 0, err
    }

	fmt.Printf("总共 IP 地址: %d\n", totalIPs)

	var processedIPs int
	var validIPCount int
	var lock sync.Mutex

	for _, cidrBlock := range cidrBlocks {
	    ips, err := generateIPs(cidrBlock)
	    if err != nil {
	        fmt.Printf("无法为 CIDR %s 生成 IP: %v\n", cidrBlock, err)
	        continue
	    }

	    for len(ips) > 0 {
	        batch := ips
	        if len(ips) > batchSize {
	            batch = ips[:batchSize]
	            ips = ips[batchSize:]
	        } else {
	            ips = nil
	        }

	        results := processIPs(batch, locationMap, totalIPs, &processedIPs, &lock)
	        if len(results) > 0 {
	            validIPCount += len(results)
	            if err := writeResults(results, outFile, processedIPs != batchSize); err != nil {
	                return validIPCount, err
	            }
	        }
	    }
    }

	return validIPCount, nil
}

func fetchCIDRBlocksFromASN(asn string) ([]string, error) {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	for attempts := 0; attempts < 5; attempts++ {
	    resp, err := http.Get(url)
	    if err != nil {
	        return nil, fmt.Errorf("无法获取 CIDR 块: %v", err)
	    }
	    defer resp.Body.Close()

	    if resp.StatusCode == http.StatusOK {
	        var response struct {
	            Data struct {
	                IPv4Prefixes []CIDRBlock `json:"ipv4_prefixes"`
	            } `json:"data"`
	        }
	        if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
	            return nil, fmt.Errorf("无法解析响应: %v", err)
	        }

	        cidrBlocks := make([]string, len(response.Data.IPv4Prefixes))
	        for i, prefix := range response.Data.IPv4Prefixes {
	            cidrBlocks[i] = prefix.Prefix
	        }
	        return cidrBlocks, nil
	    }

	    if resp.StatusCode == http.StatusTooManyRequests {
	        retryAfter := time.Second * 2
	        if retryAfterHeader := resp.Header.Get("Retry-After"); retryAfterHeader != "" {
	            if retryAfterSeconds, err := strconv.Atoi(retryAfterHeader); err == nil {
	                retryAfter = time.Duration(retryAfterSeconds) * time.Second
	            }
	        }
	        fmt.Printf("超过请求限制，%v 后重试...\n", retryAfter)
	        time.Sleep(retryAfter)
	        continue
	    }

	    return nil, fmt.Errorf("无法获取 CIDR 块: 收到状态码 %d", resp.StatusCode)
    }
	return nil, fmt.Errorf("超过最大尝试次数以获取 CIDR 块")
}

func calculateTotalIPs(cidrBlocks []string) (int, error) {
	var totalIPs int
	for _, cidr := range cidrBlocks {
	    count, err := countIPsInCIDR(cidr)
	    if err != nil {
	        fmt.Printf("无法计算 CIDR %s 中的 IP: %v\n", cidr, err)
	        continue
	    }
	    totalIPs += count
    }
	return totalIPs, nil
}

func countIPsInCIDR(cidr string) (int, error) {
    _, ipNet, err := net.ParseCIDR(cidr)
    if err != nil { 
    	return 0 ,fmt.Errorf( "无法解析 CIDR :% v" ,err )
    } 
    ones , bits:= ipNet.Mask.Size()
    return 1 << (bits - ones),nil 
} 

func generateIPs(cidr string) ([]string,error){
	var ips []string 
	ip , ipNet ,err:= net.ParseCIDR(cidr ) 
	iferr!=nil{
	  returnnil ,fmt. Errorf( "无效的CIDR :% v" ,err )
	  } 
	  forip:=ip.Mask(ipNet.Mask );ipNet.Contains(ip);inc(ip){
	  ips= append(ips ,ip.String())
	  } 
	  returnips,nil 
} 

func inc(ip net.IP){
	forj:=len(ip)-1;j>=0;j--{
	ip[j]++
	ifip[j]>0{
	break 
} 
} 
} 

func processIPs(ips []string ,locationMap map[string]location,totalIPs int ,processedIPs *int ,lock *sync.Mutex)([]result){
	var wg sync.WaitGroup 
	resultChan:=make(chan result,len(ips)) 
	thread:=make(chan struct {},*maxThreads ) 

	for _,ip:=rangeips{
	thread<-struct {}{} 
	wg.Add(1 ) 
	go func(ip string){
	defer func(){
	  <-thread 
	  wg.Done() 
	  updateProgress(processedIPs,totalIPs ,lock ) 
}() 

ifres ,err:=processIP(ip ,locationMap );err==nil{
	resultChan<-res 
} 
}(ip ) 
} 

wg.Wait() 
close(resultChan ) 

results:=make([]result ,0,len(resultChan)) 
forres:=range resultChan{
	results=append(results,res )
} 

sort.Slice(results ,func(i,j int )bool{
	returnresults[i].tcpDuration<results[j].tcpDuration 
}) 
returnresults 
} 

func processIP(ip string ,locationMap map[string]location)(result,error){
	dialer:=&net.Dialer{
	  Timeout :timeout ,
} 
start:=time.Now () 
conn ,err:=dialer.Dial( "tcp" ,net.JoinHostPort(ip,strconv.Itoa(*defaultPort))) 
iferr!=nil{
returnresult{},err 
} 
deferconn.Close() 

tcpDuration:=time.Since(start ) 
start=time.Now () 

client:=http.Client{
Transport :&http.Transport{
Dial :func(network,string addr)(net.Conn,error){
returnconn,nil 
},},Timeout :timeout ,
} 

protocol :="http://"
if*enableTLS{
	protocol= "https://" 
} 

reqURL:=protocol +requestURL 

req,_:=http.NewRequest( "GET" ,reqURL,nil ) 
req.Header.Set( "User-Agent" ,"Mozilla/5.0") 
req.Close=true  
resp ,err:=client.Do(req )  
iferr!=nil{
returnresult{},err  
}  
deferresp.Body.Close()  

duration:=time.Since(start )  
ifduration>maxDuration{
returnresult{},fmt.Errorf( "请求耗时过长")  
}  

buf:=&bytes.Buffer{}  
timeoutChan:=time.After(maxDuration )  
done:=make(chan bool )  
go func(){
_,err:=io.Copy(buf ,resp.Body )  
done<-true  
iferr!=nil{
return  
}  
}()  

select{  
case<-done:
case<-timeoutChan:
returnresult{},fmt.Errorf( "请求超时")  
}  

body:=buf  
iferr!=nil{
returnresult{},err  
}  

returnparseResult(body ,ip,tcpDuration ,locationMap )  
}  

func parseResult(body *bytes.Buffer ,ip string,tcpDuration time.Duration ,locationMap map[string]location)(result,error){
ifstrings.Contains(body.String(), "uag=Mozilla/5.0"){
ifmatches:=regexp.MustCompile(`colo=([A-Z]+)` ).FindStringSubmatch(body.String());len(matches)>1{
dataCenter:=matches[1] 
loc ,ok:=locationMap[dataCenter ] 
ifok{
fmt.Printf( "有效的 IP %s，位置 %s，延迟 %d 毫秒\n" ,ip ,loc.City,tcpDuration.Milliseconds ())  
returnresult{ip,*defaultPort,dataCenter ,loc.Region ,loc.City,sprintf("%d 毫秒" ,tcpDuration.Milliseconds()),tcpDuration},nil   
}  
fmt.Printf( "有效的 IP %s，未知位置，延迟%d 毫秒\n" ,ip,tcpDuration.Milliseconds())   
returnresult{ip,*defaultPort,dataCenter ,""," ",sprintf("%d 毫秒" ,tcpDuration.Milliseconds()),tcpDuration},nil   
}}  
returnresult{},fmt.Errorf( "无法解析结果")   
}  

func updateProgress(processedIPs *int,totalIPs int ,lock *sync.Mutex){
lock.Lock()   
deferlock.Unlock()   
*processedIPs++   
percentage:=float64(*processedIPs)/float64(totalIPs)*100   
fmt.Printf( "已完成：%d /%d 个 IP 地址 (%.2f%%)\r" ,*processedIPs,totalIPs ，percentage )   
if*processedIPs==totalIPs{   
fmt.Printf( "已完成：%d /%d 个 IP 地址 (%.2f%%)\n" ，*processedIPs,totalIPs ，percentage )   
}}  

func sortResultsByDuration(results []result){
sort.Slice(results ，func(i,j int )bool{   
returnresults[i].tcpDuration<results[j].tcpDuration   
})   
}  

func isFileEmpty(filename string)(bool,error){   
info，err:=os.Stat(filename)    
iferr!=nil{    
ifos.IsNotExist(err){    
returntrue,nil    
}    
returnfalse，err    
}    
returninfo.Size()==0,nil    
}  

func writeResults(results []result,outFile string，appendToFile bool)(error){    
iflen(results)==0{    
returnnil    
}    

file，err:=os.OpenFile(outFile，os.O_CREATE|os.O_WRONLY|os.O_APPEND，0644)    
iferr!=nil{    
returnfmt.Errorf( "无法创建文件：%v"，err）    
}    
deferfile.Close()    

writer:=csv.NewWriter(file）    
deferwriter.Flush()    

iffileInfo，err:=file.Stat();err==nil&&fileInfo.Size()==0{    
writer.Write([]string{"IP 地址"，"端口"，"TLS"，"数据中心"，"区域"，"城市"，"延迟"})    
}    

for_,res：=range results{    
writer.Write([]string{res.ip，strconv.Itoa(res.port)，strconv.FormatBool(*enableTLS)，res.dataCenter，res.region，res.city，res.latency})    
}    

returnnil    
}  

func formatDuration(d time.Duration)(string){     
h：=d/time.Hour     
m：=(d%time.Hour)/time.Minute     
s：=(d%time.Minute)/time.Second     

ifh>0{     
returnsprintf("%dh%dm%ds"，h ，m ，s）     
}else ifm>0{     
returnsprintf("%dm%ds"，m ，s）     
}else{     
returnsprintf("%ds"，s）     
}}  

func clearConsole(){     
var cmd *exec.Cmd     
switchruntime.GOOS{     
case"windows":     
cmd=exec.Command（“cmd”，“/c”，“cls”）     
case“linux”，“darwin”：     
cmd=exec.Command（“clear”）     
default：     
cmd=exec.Command（“clear”）     
}     
cmd.Stdout=os.Stdout     
cmd.Run（）     
}

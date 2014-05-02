package main

import (
        "database/sql"
        "encoding/xml"
        "flag"
        "fmt"
        _ "github.com/lib/pq"
        "log"
        "os"
        "path/filepath"
        "runtime"
        "sync"
        "time"
)

var count int = 0

type ReportHost struct {
        XMLName        xml.Name       `xml:"ReportHost"`
        HostProperties HostProperties `xml:"HostProperties"`
        ReportItemList []ReportItem   `xml:"ReportItem"`
}

type HostProperties struct {
        XMLName xml.Name   `xml:HostProperties"`
        Info    []InfoList `xml:"tag"`
}

type InfoList struct {
        Key     string  `xml:"name,attr"`
        Value   string  `xml:",chardata"`
}

type ReportItem struct {
        CVE                        []string `xml:"cve"`
        CvssBaseScore              float64  `xml:"cvss_base_score"`
        Desciption                 string   `xml:"description"`
        ExploitAvailable           bool     `xml:"exploit_available"`
        ExploitFrameworkCanvas     bool     `xml:"exploit_framework_canvas"`
        ExploitFrameworkCore       bool     `xml:"exploit_framework_core"`
        ExploitFrameworkMetasploit bool     `xml:"exploit_framework_metasploit"`
        ExploitEase                string   `xml:"exploit_ease"`
        MetasploitName             string   `xml:"metasploit_name"`
        PluginName                 string   `xml:"plugin_name"`
        RiskFactor                 string   `xml:"risk_factor"`
        Solution                   string   `xml:"solution"`
        Synopsis                   string   `xml:"synopsis"`
        PluginOutput               string   `xml:"plugin_output"`
        SeeAlso                    string   `xml:"see_also"`
        ExploitedMalware           bool     `xml:"exploited_by_malware"`
        Severity                   int      `xml:"severity,attr"`
        PluginID                   int      `xml:"pluginID,attr"`
}

type readyData struct {
        ip                string
        os                string
        mac               string
        fqdn              string
        netbios           string
        cve               []string
        cvss              float64
        desc              string
        exploitAvailable  bool
        exploitCanvas     bool
        exploitCore       bool
        exploitMetasploit bool
        exploitEase       string
        metasploitName    string
        pluginName        string
        risk              string
        solution          string
        synopsis          string
        pluginOutput      string
        seeAlso           string
        exploitedMalware  bool
        severity          int
        pluginID          int
}

func dataPrep(wg *sync.WaitGroup, prep *sql.Stmt, report *ReportHost, db *sql.DB) {
        hashmap := make(map[string]string)
        for _, host := range report.HostProperties.Info {
                hashmap[host.Key] = host.Value
        }
        var rd readyData
        rd.ip = hashmap["host-ip"]
        rd.os = hashmap["operating-system"]
        rd.mac = hashmap["mac-address"]
        rd.fqdn = hashmap["host-fqdn"]
        rd.netbios = hashmap["netbios-name"]
        for _, host := range report.ReportItemList {
                rd.cve = host.CVE
                rd.cvss = host.CvssBaseScore
                rd.desc = host.Desciption
                rd.exploitAvailable = host.ExploitAvailable
                rd.exploitCanvas = host.ExploitFrameworkCanvas
                rd.exploitCore = host.ExploitFrameworkCore
                rd.exploitMetasploit = host.ExploitFrameworkMetasploit
                rd.exploitEase = host.ExploitEase
                rd.metasploitName = host.MetasploitName
                rd.pluginName = host.PluginName
                rd.risk = host.RiskFactor
                rd.solution = host.Solution
                rd.synopsis = host.Synopsis
                rd.pluginOutput = host.PluginOutput
                rd.seeAlso = host.SeeAlso
                rd.exploitedMalware = host.ExploitedMalware
                rd.severity = host.Severity
                rd.pluginID = host.PluginID
                databaseImport(prep, &rd, db)
        }
        if verbose == 2 {
                fmt.Println("")
        }
        wg.Done()
}

func xmlParse(wg *sync.WaitGroup, xmlFile *os.File, prep *sql.Stmt, db *sql.DB) {
        decoder := xml.NewDecoder(xmlFile)
        for {
                count = 0
                t, _ := decoder.Token()
                if t == nil {
                        break
                }
                switch se := t.(type) {
                case xml.StartElement:
                        if se.Name.Local == "ReportHost" {
                                var report ReportHost
                                wg.Add(1)
                                decoder.DecodeElement(&report, &se)
                                go dataPrep(wg, prep, &report, db)
                        }
                }

        }
        wg.Done()
}

// Database import
func databaseImport(prep *sql.Stmt, d *readyData, db *sql.DB) {
        month := int(time.Now().Month())
        year := int(time.Now().Year())
        if len(d.cve) == 0 {
                d.cve = append(d.cve, "None")
        }
        for _, cve := range d.cve {
                res, err := prep.Exec(d.ip, d.mac, d.netbios, d.fqdn, d.os,
                        d.pluginName, d.pluginID, d.severity, cve, d.risk,
                        d.desc, d.solution, d.synopsis, d.pluginOutput, d.seeAlso,
                        d.exploitAvailable, d.exploitEase, d.exploitMetasploit,
                        d.metasploitName, d.exploitCanvas, d.exploitCore,
                        d.exploitedMalware, d.cvss, month, year)
                if verbose == 2 {
                        fmt.Printf("Importing %-15s Items:%4d \r", d.ip, count)
                        count += 1
                }
                if err != nil || res == nil {
                        log.Fatal(err)
                }
        }

}

func createTable(db *sql.DB, table *string) {
        var stm string = `create table if not exists ` + *table + `(id serial,
        host text,mac_address text, netbios text, fqdn text,os_name text,
        plugin_name text, plugin_id integer,severity integer, cve text,
        risk text,description text, solution text, synopsis text,
        plugin_output text, see_also text,exploit_available boolean,
        exploit_ease text,metasploit_framework boolean, metasploit_name text,
        canvas_framework boolean, core_framework boolean,
        exploited_malware boolean, cvss float,month integer, year integer)`
        prep, err := db.Prepare(stm)
        if err != nil {
                log.Fatal(err)
        }
        res, err := prep.Exec()
        if err != nil || res == nil {
                log.Fatal(err)
        }

        prep.Close()
}

func dropTable(db *sql.DB, table *string) {
        var stm string = "drop table if exists " + *table
        prep, err := db.Prepare(stm)
        if err != nil {
                log.Fatal(err)
        }
        res, err := prep.Exec()
        if err != nil || res == nil {
                log.Fatal(err)
        }
        prep.Close()
}

func coreCheck(cores *int) {
        if *cores > runtime.NumCPU() || *cores <= 0 {
                log.Fatal(`You don't have that many cores... you can use up to `,
                        runtime.NumCPU())
        } else {
                runtime.GOMAXPROCS(*cores)
                if verbose == 1 {
                        fmt.Println("Using " + string(runtime.GOMAXPROCS(*cores)) + " cores")
                }
        }
}

var verbose int

func main() {
        fileOpt := flag.String("file", "xmlFile", "file to parse into db")
        dirOpt := flag.String("dir", "directory", "dir of xml files")
        coreOpt := flag.Int("cores", 1, "Number of Cores to use")
        verboseOpt := flag.Int("verbose", 0, "Verbose level 0,1,2")
        userOpt := flag.String("user", "postgres", "User for Postgres")
        passOpt := flag.String("pass", "", "Password for Postgres user")
        dbOpt := flag.String("db", "gotest", "DB to use")
        tableOpt := flag.String("table", "internal_network", "Table to use")
        sslOpt := flag.String("ssl", "disable", "Enable or Disable")
        flag.Parse()
        coreCheck(coreOpt)
        verbose = *verboseOpt
        var con_opts string
        if *passOpt == "" {
                con_opts = "user=" + *userOpt +
                        " dbname=" + *dbOpt + " sslmode=" + *sslOpt
        } else {
                con_opts = "user=" + *userOpt + " password=" + *passOpt +
                        " dbname=" + *dbOpt + " sslmode=" + *sslOpt
        }
        db, err := sql.Open("postgres", con_opts)
        if err != nil {
                fmt.Println("Error Connecting:", err)
                return
        }
        defer db.Close()
        txn, err := db.Begin()
        if err != nil {
                log.Fatal(err)
        }
        //dropTable(db, tableOpt)
        createTable(db, tableOpt)
        prep, err := txn.Prepare(`copy ` + *tableOpt + ` (host, mac_address, netbios,
                fqdn, os_name, plugin_name, plugin_id, severity, cve,
                risk, description, solution, synopsis, plugin_output,
                see_also, exploit_available, exploit_ease, metasploit_framework,
                metasploit_name, canvas_framework, core_framework,
                exploited_malware, cvss, month, year) from stdin`)
        if err != nil {
                log.Fatal(err)
        }
        file := *fileOpt
        dir := *dirOpt
        fmt.Println("Importing..")
        var wg sync.WaitGroup
        if file != "xmlFile" {
                xmlFile, err := os.Open(file)
                defer xmlFile.Close()
                if err != nil {
                        log.Fatal(err)
                        return
                }
                wg.Add(1)
                xmlParse(&wg, xmlFile, prep, db)
        } else if dir != "directory" {
                files, _ := filepath.Glob(dir + "/*")
                for _, file := range files {
                        xmlFile, err := os.Open(file)
                        defer xmlFile.Close()
                        if err != nil {
                                log.Fatal(err)
                                return
                        }
                        if verbose == 1 {
                                fmt.Printf("Parsing %s\n", file)
                        }
                        wg.Add(1)
                        go xmlParse(&wg, xmlFile, prep, db)
                }

        }
        wg.Wait()
        if err != nil {
                log.Fatal(err)
        }
        _, err = prep.Exec()
        if err != nil {
                log.Fatal(err)
        }
        err = prep.Close()
        if err != nil {
                log.Fatal(err)
        }
        err = txn.Commit()
        if err != nil {
                log.Fatal(err)
        }
}

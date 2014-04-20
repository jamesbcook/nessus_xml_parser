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

func dataPrep(prep *sql.Stmt, report *ReportHost, db *sql.DB) {
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
        fmt.Println("")
}

func xmlParse(xmlFile *os.File, prep *sql.Stmt, db *sql.DB) {
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

                                decoder.DecodeElement(&report, &se)
                                dataPrep(prep, &report, db)
                        }
                }

        }
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

                fmt.Printf("Importing %-15s Items:%4d \r", d.ip, count)
                count += 1
                if err != nil || res == nil {
                        log.Fatal(err)
                }
        }

}

func createTable(db *sql.DB) {
        const stm string = `create table if not exists network (id serial,
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

func dropTable(db *sql.DB) {
        const stm string = "drop table if exists network"
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

func main() {
        fileOpt := flag.String("file", "xmlFile", "file to parse into db")
        dirOpt := flag.String("dir", "directory", "dir of xml files")
        flag.Parse()

        db, err := sql.Open("postgres",
                "user=postgres dbname=gotest sslmode=disable")
        if err != nil {
                fmt.Println("Error Connecting:", err)
                return
        }
        defer db.Close()
        txn, err := db.Begin()
        if err != nil {
                log.Fatal(err)
        }
        //dropTable(db)
        createTable(db)
        prep, err := txn.Prepare(`copy network (host, mac_address, netbios,
                fqdn, os_name, plugin_name, plugin_id, severity, cve,
                risk, description, solution, synopsis, plugin_output,
                see_also, exploit_available, exploit_ease, metasploit_framework,
                metasploit_name, canvas_framework, core_framework,
                exploited_malware, cvss, month, year) from stdin`)
        file := *fileOpt
        dir := *dirOpt
        if file != "xmlFile" {
                xmlFile, err := os.Open(file)
                defer xmlFile.Close()
                if err != nil {
                        log.Fatal(err)
                        return
                }
                xmlParse(xmlFile, prep, db)
        } else if dir != "directory" {
                files, _ := filepath.Glob(dir + "/*")
                for _, file := range files {
                        xmlFile, err := os.Open(file)
                        defer xmlFile.Close()
                        if err != nil {
                                log.Fatal(err)
                                return
                        }
                        fmt.Printf("Parsing %s\n", file)
                        xmlParse(xmlFile, prep, db)
                }

        }
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

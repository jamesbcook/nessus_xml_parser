package main

import (
        "bytes"
        "database/sql"
        "encoding/xml"
        "flag"
        "fmt"
        _ "github.com/lib/pq"
        "log"
        "os"
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

func insertStatement(db *sql.DB) string {
        var stm bytes.Buffer
        stm.WriteString("insert into network (host, mac_address, netbios, ")
        stm.WriteString("fqdn, os_name, plugin_name, plugin_id, severity, ")
        stm.WriteString("cve, risk, description, solution, synopsis, ")
        stm.WriteString("plugin_output, see_also, exploit_available, ")
        stm.WriteString("exploit_ease, metasploit_framework, metasploit_name, ")
        stm.WriteString("canvas_framework, core_framework, exploited_malware, ")
        stm.WriteString("cvss, month, year) values ($1,$2, $3, $4, $5, $6, ")
        stm.WriteString("$7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, ")
        stm.WriteString("$18, $19, $20, $21, $22, $23, $24, $25)")
        return stm.String()
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

                fmt.Printf("Importing %-12s Items:%d\r", d.ip, count)
                count += 1
                if err != nil || res == nil {
                        log.Fatal(err)
                }
        }

}

func createTable(db *sql.DB) {
        var stm bytes.Buffer
        stm.WriteString("create table if not exists network (id serial, host text, ")
        stm.WriteString("mac_address text, netbios text, fqdn text, ")
        stm.WriteString("os_name text, plugin_name text, plugin_id integer, ")
        stm.WriteString("severity integer, cve text, risk text, ")
        stm.WriteString("description text, solution text, synopsis text, ")
        stm.WriteString("plugin_output text, see_also text, ")
        stm.WriteString("exploit_available boolean, exploit_ease text, ")
        stm.WriteString("metasploit_framework boolean, metasploit_name text, ")
        stm.WriteString("canvas_framework boolean, core_framework boolean, ")
        stm.WriteString("exploited_malware boolean, cvss float, ")
        stm.WriteString("month integer, year integer)")
        prep, err := db.Prepare(stm.String())
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
        stm := "drop table if exists network"
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
        file := flag.String("file", "xmlFile", "file to parse into db")
        flag.Parse()
        xmlFile, err := os.Open(*file)
        if err != nil {
                fmt.Println("Error opening file:", err)
                return
        }
        defer xmlFile.Close()

        db, err := sql.Open("postgres",
                "user=postgres dbname=gotest sslmode=disable")
        if err != nil {
                fmt.Println("Error Connecting:", err)
                return
        }
        defer db.Close()
        dropTable(db)
        createTable(db)
        stm := insertStatement(db)
        prep, err := db.Prepare(stm)
        if err != nil {
                log.Fatal(err)
        }
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
        prep.Close()
}

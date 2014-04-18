nessus_xml_parser
=================

Parse Nessus XML file and insert into a db


Run the Bin or build your self

### Build

Install PG lib

`go get github.com/lib/pq`

Make binary

`go build nessues_xml_parser.go`

Run source

`go run nessues_xml_parser.go`


### Table Layout

 id | host | mac_address | netbios | fqdn | os_name |  plugin_name | plugin_id | severity | cve | risk | description | solution | synopsis | plugin_output | see_also | exploit_available | exploit_ease | metasploit_framework | metasploit_name  | canvas_framework | core_framework | exploited_malware | cvss | month | year 

nessus_xml_parser
=================

Parse Nessus XML file and insert into a db

### ./nessus_xml_parser -h

    Usage of ./nessus_xml_parser:

      -cores=1: Number of Cores to use
  
      -db="gotest": DB to use
  
      -dir="directory": dir of xml files
  
      -file="xmlFile": file to parse into db
  
      -pass="": Password for Postgres user
  
      -ssl="disable": Enable or Disable
  
      -table="internal_network": Table to use
  
      -user="postgres": User for Postgres
  
      -verbose=0: Verbose level 0,1,2

### Example

    /nessus_xml_parser -cores 4 -dir /home/user/xmlDir/ -table testing

### Build

Install PG lib

`go get github.com/lib/pq`

Make binary

`go build nessues_xml_parser.go`

Run source

`go run nessues_xml_parser.go`


### Table Layout

id | host | mac_address | netbios | fqdn | os_name |  plugin_name | plugin_id | severity | cve | risk | description | solution | synopsis | plugin_output | see_also | exploit_available | exploit_ease | metasploit_framework | metasploit_name  | canvas_framework | core_framework | exploited_malware | cvss | month | year 
--- | --- | --- | --- | --- | --- |--- | --- | --- |--- | --- | --- |--- | --- | --- |--- | --- | --- |--- | --- | --- |--- | --- | --- |--- | --- |


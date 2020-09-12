# Information Stealers Wall of Sheep (IS-WOS)

__Note: The old mappings and data are not longer maintained and will be removed in upcoming updates. Use the new ECS-compliant mappings and data in ```is-wos-ecs-data.ndjson```, ```is-wos-ecs-mappings.json``` and ```is-wos-ecs-ingest-pipeline.json```.__

- Similar to DEF CON's Wall of Sheep, but for information stealers and keyloggers that mostly operate over SMTP and FTP. Information stealer families include AgentTesla, HawkEye, MassLogger, M00nD3v, Phoenix, AspireLogger, and Orion Logger. Only unique hashes are considered. All Timestamps are in UTC.
- Using password analysis and correlation, among other data pivot points, it is possbile to cluster sheep into identifiable herds.
- Collect static file properties as enrichment data points, including imaphash, ssdeep, debug paths, compilers, libraries, packers, protectors, and metadata.

![image](https://github.com/ditekshen/is-wos/raw/master/img/dashboard_snapshot_20200912.jpg)

## Observations and Analysis

See the [Analysis.md](https://github.com/ditekshen/is-wos/blob/master/Analysis.md) document for details.

## Yara Rules

Three Yara rules exist. One for email addresses, another for the domains within these addresses, and the final one is for the passwords. The passwords rule will generate false positives.

## Ingesting Data

### Elasticsearch

   Assuming Elasticsearch and Kibana are installed and ready to ingest data:

   1. To properly generate geo-location and ASN information, make sure you have up-to-date (free) MaxMind databases:
    
       GeoLite2-ASN.mmdb, GeoLite2-City.mmdb, and GeoLite2-Country.mmdb stored in the "ingest-geoip" plugin/ingest pipeline directory, for example:
    
       ```
       /usr/share/elasticsearch/modules/ingest-geoip/GeoLite2-ASN.mmdb
       /usr/share/elasticsearch/modules/ingest-geoip/GeoLite2-City.mmdb
       /usr/share/elasticsearch/modules/ingest-geoip/GeoLite2-Country.mmdb
       ```
    
       Note: Elasticsearch service may need to be restarted to pick up the new/updated databases.
    
   2. Select "Machine Learning" from Kibana's sidebar. This is availble in the free "Basic" Elastic Stack subscriptions and is enabled by default.
   3. Click "Upload file" under "Import data", and then select or drag the is-wos-ecs-data.ndjson file.
   4. In the resulting sampling page, click "Import".
   5. Add a name for the index and create the index pattern if it does not exist or this is first time the data is being imported.
   5. In the "Import data" page, select "Advanced" and perform the following:
      - Copy the contents of the is-wos-ecs-mappings.json into the "Mappings" field replacing the existing one.
      - Copy the contents of the is-wos-ecs-ingest-pipeline.json into the "Ingest pipeline" field replacing the existing one.
   6. Click "Import".
   
   At this stage, the data should be imported and ready for search and visualization.

### Splunk

   ECS mappings were not tested on Splunk. Assuming Splunk is installed and ready to ingest data:

   1. On Splunk landing page, click "Add Data".
   2. On Splunk "adddata" page, click "Upload".
   3. On the "Select Source", select the is-wos-data.json file, then click "Next".
   4. In the "Set Source Type" page, exapnd the "Timestamp" left menu and enter the below values in the corresponding fields. Ensure that there are no pasrsing errors before proceeding.
      - Timestamp format: %Y-%m-%d
      - Timestamps fields: observed
   5. On the "Input Settings" page, either modify the Host and Index or simply proceed with click "Review" and then "Submit".

   At this stage, the data should be imported and ready for search and visualization.

## Disclaimer

The published data is for research purposes only, and not to be used for any malicious intents or purposes. Malicious use of the data is punishable by law regardless of jurisdiction. The owner/author of this data does not take any responsibility if the data is used maliciously or to perform criminal activities.

## Acknowledgments

- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)
- [DIE](https://github.com/horsicq/Detect-It-Easy)
- [Manalyze](https://github.com/JusticeRage/Manalyze)
- [CAPA](https://github.com/fireeye/capa)
- [Elasticsearch and Kibana](https://www.elastic.co/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## To-Do

- ~~Create an ECS-compliant field mappings.~~ (Done)
- ~~Add enrichment data.~~ (Done)
- Create standard visualiztions and dashboard.
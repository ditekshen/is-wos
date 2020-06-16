# Information Stealers Wall of Sheep (IS-WOS)

- Similar to DEF CON's Wall of Sheep, but for information stealers and keyloggers that mostly operate over SMTP and FTP. Information stealer families include AgentTesla, HawkEye, MassLogger, M00nD3v, Phoenix, AspireLogger, and Orion Logger. Only unique hashes are considered. All Timestamps are in UTC.
- Using password analysis and correlation, it is possbile to cluster sheep into identifiable herds.

![image](https://github.com/ditekshen/is-wos/raw/master/img/dashboard_snapshot_20200615.jpg)

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
   3. Click "Upload file" under "Import data", and then select or drag the is-wos-data.ndjson file.
   4. In the resulting sampling page, under "Override settings" ensure that the "Time field" is set to "observed", and then click "Import".
   5. Add a name for the index and create the index pattern if it does not exist or this is first time the data is being imported.
   5. In the "Import data" page, select "Advanced" and perform the following:
      - Copy the contents of the is-wos-mappings.json into the "Mappings" field replacing the existing one.
      - Copy the contents of the is-wos-ingest-pipeline.json into the "Ingest pipeline" field replacing the existing one.
   6. Click "Import".
   
   At this stage, the data should be imported and ready for search and visualization.

### Splunk

   Assuming Splunk is installed and ready to ingest data:

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

## To-Do

- Create an ECS-compliant field mappings.
- Create standard visualiztions and dashboard.
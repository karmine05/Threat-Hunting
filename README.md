# Threat-Hunting
Learn how to threat hunt leveraging Jupiter NoteBook and Apache Spark.

# Environment :

### Hosts: 

```
A. Sun ==> ADDNS Server

B. Earth ==> Workstation
```

The Sample Data at the moment consists of some TTP's generated via RedCanary's 'atomic-red-team'. [Not 100% coverage]

LINK: https://redcanary.com/atomic-red-team/

The way the data has been shared is a Parquet file to compress apprx. 30 days worth of Data and also make the data sharable. 

Over the next couple of weeks I will be releasing more data sets to enable hunting and sharing and re-utilizing the Jupyter Codes. 



# Requirements :

A. Apache Spark.

B. JupyterNoteBook. 

C. untar the `edr_all_raw.parquet.tar` 
```
tar -xvf edr_all_raw.parquet.tar
```

# Purpose :

When I started the journey to Leverage Apache Spark and Python to crunch through terabytes of data, i didn't find much useable documents nor easyly shareble codes. Thus releasing this dataset along with the NupyterNotebooks and will provide more codes and dataset in future. 

# Future Works :

A. [+] more codes.

B. [+] cover more event_ids from Sysmon & windows security events.

C. [+] Lets Create a SIGMA to SQL converter.


# Issues :

[-] The current dataset provided doesn't have 2 fields that are part of the codebase - Description, IntegrityLevel.
    [These won't impact the actual codes and if you use your own datasets The NoteBook will run with out nay issues. The missing fields are only being used in few usecase, so you should be able to run 90% of the code with out any issues. ] 

```
[N.B => These fields will be available with the new datasets. ]
```

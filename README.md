## capMe! - Splunk Edition

This edition builds on the changes that Security Onion made in their ELK implementation.  

This script can be utilized in conjunction with any running Security Onion Master/Standalone.  It is best to populate the web form  automatically through a Splunk follow on action or custom drilldown.

Example URI:

`https://host/capme/splunk.php?spid=$SPID$&stime=$EPOCHTIME$%sourcetype=$sourcetype$`

SPID is an eval field I created by MD5 hashing the \_cd and \_bkt fields with a \_ between them. So the final entry within my props.conf looked like this:

`EVAL-spid = md5(_bkt+"_"+_cd)`

I'm currently looking for a different solution then this because I don't really like having that SPID field.  I created this to replicate the way ELK's implemenation of CapME searches for the event calling it.

The user that is logging into the Security Onion webserver needs to have an account on Splunk with the same creds.

## Requirements

* A SPID field that is relatively unique
* A time field in epoch time
* An entry in the security.conf with the following information
  - SPLUNK_HOST=(The machine that searches Splunk Indexes)
  - SPLUNKD_PORT=(The splunkd port, typically 8089)
* A user account in Splunk with the same user information for the account that was used to log into Security Onion

### Old readme below

## capME!

Easy bake oven for sguil transcripts

## Provides

* cliscript.tcl which can be used from the command line to generate a transcript
* a web front end that will let you:
       
1) Fill in form fields and click a button to get a transcript or,

2) Automagically populate and submit the form by supplying the fields in the URI:
      
`https://host.ca/capme/index.php?sip=10.10.10.1&spt=4242&dip=10.10.10.2&dpt=80&ts=2012-11-27%2005:34:00&usr=paulh&pwd=aBcDeF`
 

## Notes

 * If no sid is supplied the script takes a peek in the sancp table to find an appropriate one.  
 * If you aren't using securityonion then two sguild libs need minor patches for this to work. Take a peek in the patches folder.

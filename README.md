# BurpThenFuzz

Export the history tab from burp and pass it to this script.

The script will:
* Take in a scope/target
* Modify XML doc version, first line from 1.1 to 1.0
* Run analytics and statistics [TODO] 
* Fuzz GET requests parameters
* Fuzz POST requests parameters
* Pass Through a Proxy
* Analyze Parameters [TODO]
* Handle other HTTP Methods [TODO]
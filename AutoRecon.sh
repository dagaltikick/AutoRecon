#!/bin/bash
# set vars
id="$1"
ppath="$(pwd)"
scope_path="$ppath/scope/$id"
timestamp="$(date "+%Y%m%d%H%M%S")"
scan_path="$ppath/scans/$id-$timestamp"
# exit if scope path doesnt exist
if [ ! -d "$scope_path" ]; then echo "Path doesn't exist" exit 1
fi
mkdir -p "$scan_path" cd "$scan_path"
### PERFORM SCAN ### 
echo "Starting scan against roots:" 
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt" 
cat "$scan_path/roots.txt" | subfinder | anew subs.txt
cat "$scan_path/roots.txt" | shuffledns -w "$ppath/lists/pry-dns.txt" -r "$ppath/lists/resolvers.txt" | anew subs.txt
cat subs.txt | grep $1 > $scan_path/subs.txt
#resolve-Discover-subdomains
echo ==============================================
echo "+++Bruteforcing the Wildcard DNS entries++++"
echo ==============================================
puredns resolve "$scan_path/subs.txt" -r "$ppath/lists/resolvers.txt" -w "$scan_path/resolved.txt" | wc -l
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json" | jq -r '.a?[]?' | anew "$scan_path/ips.txt" | wc -l
#port scanning & HTTP Server Discovery
echo ========================================================
echo "++++Performing Port scan to find the HTTP Services++++"
echo ========================================================
#nmap -T4 -vv --script=http-title -iL "$scan_path/resolved.txt" -p 443 -n --open -oX "$scan_path/nmap.xml"
#tew -x "$scan_path/nmap.xml" -dnsx "$scan_path/dns.json" --vhost -o "$scan_path/hostport.txt" | httpx -json -o "$scan_path/http.json"

#cat "$scan_path/http.json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u "$scan_path/http.txt"

#grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' "$scan_path/http.txt" > "$scan_path/http-ip.txt"

#grep -vFf httpip.txt http.txt > "$scan_path/http.txt"
httpx -p https:80-5000 -ec -t 500 -l "$scan_path/resolved.txt" -o "$scan_path/http.txt"
echo ===========================================
echo "++++directory BruteForce++++"
echo ===========================================
dirsearch -l "$scan_path/http.txt"  --recursion-status=200 --skip-on-status=300-499 -o "$scan_path/dirfuzz.txt"
#http resposne capture
echo ===========================================
echo "++++HTTP Resposne capture++++"
echo ===========================================
httpx -l "$scan_path/http.txt" -sr -srd "$scan_path/responses" -json -o "$scan_path/http.json"
#crwawling
gospider -S "$scan_path/http.txt" | grep "{" | jq -r '.output?' | tee "$scan_path/crawl.txt"
#save JS file with crawled URLs
cat "$scan_path/crawl.txt" | grep "\.js" | httpx -sr -srd "$scan_path/js" 
echo ===========================================
echo "++++Nuclei Scan+++"
echo ===========================================
cat "$scan_path/dirfuzz.txt" | sed -nE 's~.*(https?://[^[:space:]]+).*~\1~p' > "$scan_path/dirfuzz.txt"
nuclei -list "$scan_path/dirfuzz.txt" -o "$scan_path/nuclei.txt"


#######ADD SCAN LOGIC HERE ############
# calculate time diff
end_time=$(date +%T)
seconds="$(expr $end_time - $timestamp)"
time=""
if [[ "$seconds" -gt 59 ]] 
then
    minutes=$( echo "scale=2; $seconds / 60" | bc )
    time="$minutes minutes"
else
    time="$seconds seconds"
fi
echo "Scan $id took $time"

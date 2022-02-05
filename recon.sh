#!/bin/bash

domain=$1

domain_enum(){
	echo "########### creating dir #########"
	mkdir -p $domain/sources $domain/intel $domain/intel/nuclei $domain/vulnfile

	echo "###### find domain using subfinder ####"
	subfinder -d $domain/sources/subfinder.txt

	echo"##### find domain using assetfinder ####"
	assetfinder -subs-only $domain | tee -a $domain/sources/assetfinder.txt

	echo"#### find domain using amass ####"
	amass enum -passive -d $doamin | tee -a $domain/sources/amass.txt


	cat $domain/sources/*.txt >> $domain/sources/all.txt

	cat $domain/sources/all.txt | sort -u | tee -a $domain/sources/all1.txt

	cat $domain/sources/all1.txt | qsreplace | httpx -follow-redirects -silent >> $domain/sources/resolved.txt

	cat $domain/sources/resolved.txt | cut -d : -f2 | cut -c 3- >> $domain/sources/live_domains.txt
}
domain_enum

# get all available hidden directories from subdomains

hidden_dir(){	
	python3 /root/tools/dirsearch/dirsearch.py -L $domain/sources/live-domain.txt -w /usr/share/wordlists/dirbuster/directory-list-2.3-      		small.txt -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk,tar --simple-report 		dirsearch_output.txt > $domain/sources/subdomains_content_discovery.txt
}
hidden_dir

#get all available endpoint using wayback machine and filter the results

waybackurl_machine(){
	cat $domain/sources/live_domains.txt | waybackurls | grep -v -e .css -e .jpg -e .jpeg -e png -e ico -e svg >$domain/sources/waybackurl.txt
	cat $domain/sources/live_donains.txt | gau | grep -v -e .css -e .jpg -e .jpeg -e png -e ico -e svg >> $domain/sources/waybackurl.txt
	cat $domain/sources/waybackurl.txt | qsreplace | httpx -silent -follow-redirects > $domain/sources/waybackurls.txt
	rm -rf $domain/sources/waybackurl.txt

waybackurl_machine

#get the js files from the output wayback machine results

waybackjs_file(){
	cat $domain/sources/waybackurls.txt | grep ".js" > $domain/sources/jsfiles
}
waybackjs_file

#make possible vulnerable files by gf 

gfvul_file(){
	cat $domain/sources/waybackurls.txt | grep = | gf ssrf > $domain/vulnfile/ssrf.txt
	cat $domain/sources/waybackurls.txt | grep = | gf sqli > $domain/vulnfile/sqli.txt
	cat $domain/sources/waybackurls.txt | grep = | gf xss > $domain/vulnfile/xss.txt
	cat $domain/sources/waybackurls.txt | grep = | gf lfi > $domain/vulnfile/lfi.txt
	cat $domain/sources/waybackurls.txt | grep = | gf idor > $domain/vulnfile/idor.txt

	cat $domain/sources/waybackurls.txt | grep = | gf redirect > $domain/vulnfile/redirect.txt
	cat $domain/sources/waybackurls.txt | grep = | gf rce > $domain/vulnfile/rce.txt
}
gfvul_file

#    httprobe_Tool(){
#	cat $domain/source/all1.txt | httprobe | tee -a $domain/intel/httprobe.txt
# }
#   httprobe_Tool */



nuclei_scannertest(){
	echo "#### Nuclei Running #####"
	cat $domain/intel/httprobe.txt | nuclei -t /root/nuclei-templates/cves/ -c 100 -o $domain/intel/nuclei/cves.txt
	cat $domain/intel/httprobe.txt | nuclei -t /root/nuclei-templates/vulnerablities/ -c 100 -o $domain/intel/nuclei/vulnerablity.txt
	cat $domain/intel/httprobe.txt | nuclei -t /root/nuclei-templates/takeovers/ -c 100 -o $domain/intel/nuclei/takeover.txt
        cat $domain/intel/httprobe.txt | nuclei -t /root/nuclei-templates/misconfiguration/ -c 100 -o $domain/intel/nuclei/misconfig.txt
}
nuclei_scannertest

echo "Now looking for Cors Misconfiguration"

cors_test(){
	python3 /root/tools/Corsy-master/corsy.py -i $domain/intel/httprobe.txt -t 40 | tee -a $domain/intel/corsy_op.txt
}
cors_test

echo " Now looking for HTTP request smuggling "

sumggler_test(){
	python3 /root/tools/smuggler.py -u $domain/intel/smuggler_op.txt
}
sumggler_test

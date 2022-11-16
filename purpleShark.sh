#!/bin/bash

#This is a proof of concept for the Sombreros Morados group project.
#The project is a bash script that reads Pcap files called: purpleShark.sh
#This bash script is looking for HTTP Requests, Possible Login Attempts, Email addresses and other credentials, exporting objects (dicom, http, smtp, tftp, imf), Basic IP Statistics, and All Protocols used within the pcap file.
#The if-then statement below starts PurpleShark if the user selects the yes button
#The zenity command below greets the user and asks them if they want to use PurpleShark
if zenity --question --text="Welcome to PurpleShark =) \n Shall we analyze a pcap? "
then

#The line below this is how zenity allows users to visually pick a pcap file (graphically)
pcapName=$(zenity --file-selection --title="Select the pcap file you want to analyze." --file-filter="*.pcap")

echo -e "\e[1;32mHave patience young grasshopper, I am analyzing your Pcap."

#Make an all purpose directory
mkdir Purple

#Let's start our functionality

mkdir ./Purple/Logins
#Search for Login Instances, Output instances to /Login directory

echo -ne '\e[1;35mProgress ####                      (20%)\r'

tshark -r $pcapName | grep --color=always -i -E 'auth|denied|login|user|usr|success|psswd|pass|pw|logon|key|cipher|sum|token|pin|code|fail|correct|restrict' > ./Purple/Logins/possible_logins.txt
tshark -Q -z credentials -r $pcapName > ./Purple/Logins/credentials.txt

#Search for IP instances, show basic IP statistics, mkdir IP_Info, outpout files to IP_Info

mkdir ./Purple/IP_Info

echo -ne '\e[1;35mProgress ########                  (40%)\r'

#Grep for ALL IP's (Source and Destination)
tshark -Q -r $pcapName -T fields -e ip.src -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/all_addresses.txt

#Grep for ALL Source IP Addresses
tshark -Q -r $pcapName -T fields -e ip.src | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/source_addresses.txt

#Grep for All Destination IP Addresses
tshark -Q -r $pcapName -T fields -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/destination_addresses.txt

#Read for all mac addresses (source or destination) make MAC_Addresses directory, dump file
mkdir ./Purple/MAC_Addresses

tshark -Q  -nqr $pcapName -z endpoints,eth > ./Purple/MAC_Addresses/mac_addresses.txt

#Search for Objects within the Pcap, make an Objects directory, dump the files /Objects
mkdir ./Purple/Objects

echo -ne '\e[1;35mProgress ############              (60%)\r'

#The tshark commands below search for various objects to export from the user selected pcap
tshark -Q -r $pcapName --export-objects imf,./Purple/Objects
tshark -Q -r $pcapName --export-objects dicom,./Purple/Objects
tshark -Q -r $pcapName --export-objects smb,./Purple/Objects
tshark -Q -r $pcapName --export-objects tftp,./Purple/Objects
tshark -Q -r $pcapName --export-objects http,./Purple/Objects


#Grep for Unencrypted Emails and make directory called Emails to dump files into

mkdir ./Purple/Emails

#Verbose

tshark -Q -r $pcapName -T fields -e text | grep --color=always -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > ./Purple/Emails/verbose_email_packets.txt

#Non-Verbose
tshark -r $pcapName | grep --color=always -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > ./Purple/Emails/email_packets.txt

#Search for ALL instances of GET/POST/HEAD requests in the pcap, make directory for HTTP_Requests

mkdir ./Purple/HTTP_Requests

echo -ne '\e[1;35mProgress #################         (80%)\r'

tshark -Vr $pcapName | grep --color=always -Eo '(GET|POST|HEAD) .* HTTP/1.[01]|Host: .*' | sort | uniq -c | sort -n > ./Purple/HTTP_Requests/http_requests.txt

#Search for ALL instances of protocols (tcp,smtp,etc.) and make a directory to dump the file into
mkdir ./Purple/Protocols

tshark -r $pcapName -T fields -e frame.protocols | sort | uniq -c | sort -n -r > ./Purple/Protocols/protocols.txt

#Test to see if the created files are empty (have zero bytes) with test -s
test ! -s "./Purple/Emails/email_packets.txt" && rm -f "./Purple/Emails/email_packets.txt"
test ! -s "./Purple/Emails/verbose_email_packets.txt" && rm -f "./Purple/Emails/verbose_email_packets.txt"
test ! -s "./Purple/HTTP_Requests/http_requests.txt" && rm -f "./Purple/HTTP_Requests/http_requests.txt"
test ! -s "./Purple/IP_Info/all_addresses.txt" && rm -f "./Purple/IP_Info/all_addresses.txt"
test ! -s "./Purple/IP_Info/destination_addresses.txt" && rm -f "./Purple/IP_Info/destination_addresses.txt"
test ! -s "./Purple/IP_Info/source_addresses.txt" && rm -f "./Purple/IP_Info/source_addresses.txt"
test ! -s "./Purple/Logins/credentials.txt" && rm -f "./Purple/Logins/credentials.txt"
test ! -s "./Purple/Logins/possible_logins.txt" && rm -f "./Purple/Logins/possible_logins.txt"
test ! -s "./Purple/Protocols/protocols.txt" && rm -f "./Purple/Protocols/protocols.txt"


#Test whether the ./Purple/Objects directory has any files. Delete if empty.

objectsDirSize=$(ls ./Purple/Objects | wc -l)

if [ ! $objectsDirSize -gt 0 ]

then
	rm -rf ./Purple/Objects

fi

echo -ne '\e[1;35mProgress #######################   (100%)\r'
echo -ne '\e[0;37m\n'

sleep 0.5

tree -s ./Purple

#The zenity command below informs the user when the PurpleShark pcap scan is complete
zenity --info --text="Pcap scan complete. All output is in the 'Purple' directory.\nThanks for using PurpleShark!!!\nNOTE - If a directory/file is empty, the program did not find the information."

#The below fi statement marks the end of the original if-then statement
fi

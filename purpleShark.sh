#!/bin/bash
set -e

function check_dependencies() {
    local missing_dependencies=()

    if ! command -v tshark &> /dev/null; then
        missing_dependencies+=("TShark")
    fi

    if ! command -v zenity &> /dev/null; then
        missing_dependencies+=("Zenity")
    fi

    if [ ${#missing_dependencies[@]} -eq 0 ]; then
        return 0
    else
        echo -e "The following dependencies are missing:"
        for dep in "${missing_dependencies[@]}"; do
            # Using ANSI color codes for red text
            echo -e "\033[31m- $dep\033[0m"
        done
        exit 1
    fi
}

function welcome_message() {
    if zenity --question --text="Welcome to PurpleShark =) \n Shall we analyze a pcap? "
    then
        return 0
    else
        echo "User chose not to proceed."
        exit 1
    fi
}

function select_pcap() {
    pcapName=$(zenity --file-selection --title="Select the pcap file you want to analyze." --file-filter="*.pcap")
    if [ -z "$pcapName" ]
    then
        echo "Error: No pcap file selected." >&2
        exit 1
    fi
    echo $pcapName
}

function create_directories() {
    mkdir -p Purple/{Logins,IP_Info,MAC_Addresses,Objects,Emails,HTTP_Requests,Protocols}
}

function extract_logins() {
    pcapName=$1
    tshark -r "$pcapName" | grep --color=always -i -E 'auth|denied|login|user|usr|success|psswd|pass|pw|logon|key|cipher|sum|token|pin|code|fail|correct|restrict' > ./Purple/Logins/possible_logins.txt
    tshark -Q -z credentials -r "$pcapName" > ./Purple/Logins/credentials.txt
}

function extract_ip_info() {
    pcapName=$1
    tshark -Q -r "$pcapName" -T fields -e ip.src -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/all_addresses.txt
    tshark -Q -r "$pcapName" -T fields -e ip.src | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/source_addresses.txt
    tshark -Q -r "$pcapName" -T fields -e ip.dst | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort | uniq -c | sort -n -r > ./Purple/IP_Info/destination_addresses.txt
}

function extract_mac_addresses() {
    pcapName=$1
    tshark -Q  -nqr "$pcapName" -z endpoints,eth > ./Purple/MAC_Addresses/mac_addresses.txt
}

function extract_objects() {
    pcapName=$1
    tshark -Q -r "$pcapName" --export-objects imf,./Purple/Objects
    tshark -Q -r "$pcapName" --export-objects dicom,./Purple/Objects
    tshark -Q -r "$pcapName" --export-objects smb,./Purple/Objects
    tshark -Q -r "$pcapName" --export-objects tftp,./Purple/Objects
    tshark -Q -r "$pcapName" --export-objects http,./Purple/Objects
}

function extract_http_requests() {
    pcapName=$1
    tshark -r "$pcapName" -Y http.request -T fields -e http.request.method -e http.request.uri -e http.host -e ip.src -e eth.src | sort | uniq -c | sort -n > ./Purple/HTTP_Requests/http_requests.txt
}

function extract_emails() {
    pcapName=$1
    tshark -r "$pcapName" -T fields -e frame.number -e ip.src | awk '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b/ {print $0}' > ./Purple/Emails/verbose_email_packets.txt
    tshark -r "$pcapName" | grep --color=always -E "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" > ./Purple/Emails/email_packets.txt
}

function extract_protocols() {
    pcapName=$1
    tshark -r "$pcapName" -T fields -e frame.protocols | sort | uniq -c | sort -n -r > ./Purple/Protocols/protocols.txt
}

function analyze_pcap() {
    pcapName=$1
    extract_logins "$pcapName"
    extract_ip_info "$pcapName"
    extract_mac_addresses "$pcapName"
    extract_objects "$pcapName"
    extract_emails "$pcapName"
    extract_http_requests "$pcapName"
    extract_protocols "$pcapName"
}

function cleanup() {
    # Test to see if the created files are empty (have zero bytes) with test -s
    test ! -s "./Purple/Emails/email_packets.txt" && rm -f "./Purple/Emails/email_packets.txt"
    test ! -s "./Purple/Emails/verbose_email_packets.txt" && rm -f "./Purple/Emails/verbose_email_packets.txt"
    test ! -s "./Purple/HTTP_Requests/http_requests.txt" && rm -f "./Purple/HTTP_Requests/http_requests.txt"
    test ! -s "./Purple/IP_Info/all_addresses.txt" && rm -f "./Purple/IP_Info/all_addresses.txt"
    test ! -s "./Purple/IP_Info/destination_addresses.txt" && rm -f "./Purple/IP_Info/destination_addresses.txt"
    test ! -s "./Purple/IP_Info/source_addresses.txt" && rm -f "./Purple/IP_Info/source_addresses.txt"
    test ! -s "./Purple/Logins/credentials.txt" && rm -f "./Purple/Logins/credentials.txt"
    test ! -s "./Purple/Logins/possible_logins.txt" && rm -f "./Purple/Logins/possible_logins.txt"
    test ! -s "./Purple/Protocols/protocols.txt" && rm -f "./Purple/Protocols/protocols.txt"

    # Test whether the ./Purple/Objects directory has any files. Delete if empty.
    if [ $(ls -A ./Purple/Objects | wc -l) -eq 0 ]
    then
        rm -rf ./Purple/Objects
    fi
}

function finish() {
    sleep 0.5
    tree -s ./Purple
    zenity --info --text="Pcap scan complete. All output is in the 'Purple' directory.\nThanks for using PurpleShark!!!\nNOTE - If a directory/file is empty, the program did not find the information."
}

function progress_bar() {
    local total=$1
    local current=$2
    local filled=$((current*20/total))
    local empty=$((20-filled))
    echo -ne "\rProgress: [${filled//?/#}${empty//?/-}] $((100*current/total))%"
}

function main() {
    check_dependencies
    welcome_message
    pcapName=$(select_pcap)
    create_directories
    progress_bar 7 1
    extract_logins "$pcapName"
    progress_bar 7 2
    extract_ip_info "$pcapName"
    progress_bar 7 3
    extract_mac_addresses "$pcapName"
    progress_bar 7 4
    extract_objects "$pcapName"
    progress_bar 7 5
    extract_emails "$pcapName"
    progress_bar 7 6
    extract_http_requests "$pcapName"
    progress_bar 7 7
    extract_protocols "$pcapName"
    cleanup
    finish
}

main


# Github based differential scan of IP addresses using VirusTotal API

import requests
import pandas as pd
import time
import ipaddress
from datetime import datetime, timezone
from github import Github
import base64
import io

global github_api_token
github_api_token = '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'
csv_file_path = 'vir_git.csv'

def update_github_file(api_token, repo_owner, repo_name, branch_name, file_path, df):
    # Initialize the GitHub API client
    github = Github(api_token)

    # Get the repository and file content
    repo = github.get_repo(f"{repo_owner}/{repo_name}")
    file_content = repo.get_contents(file_path, ref=branch_name)

    # Encode DataFrame to bytes
    updated_content = df.to_csv(index=False, encoding='utf-8')

    # Write the DataFrame to the csv file in a bytes buffer
    buffer = io.BytesIO(updated_content.encode('utf-8'))
    content = buffer.read()

    try:
        # Update the file on GitHub
        repo.update_file(
            file_path,
            message="Update file with new data",
            content=content,
            sha=file_content.sha,
            branch=branch_name
        )
        print("File updated successfully on GitHub.")
    except Exception as e:
        print(f"Error updating file on GitHub: {e}")

api_token = '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'
repo_owner = 'ProSehran'
repo_name = 'postmantest'
branch_name = 'main'
file_path = 'vir_git.csv'

   
def is_valid_ip(ip_address):
    try:
        ip_obj = ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def check_ip_virustotal(api_key, ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        response_data = response.json()
        
        last_analysis_stats = response_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = last_analysis_stats.get("malicious", 0)
        sus = last_analysis_stats.get("suspicious", 0)
        
        link = f"https://www.virustotal.com/gui/ip-address/{ip_address}/detection"
        country = response_data.get("data", {}).get("attributes", {}).get("country")   
        whois_date_utc = response_data.get("data", {}).get("attributes", {}).get("whois_date")      
        last_modification_date_utc = response_data["data"]["attributes"]["last_modification_date"]
        as_owner = response_data.get("data", {}).get("attributes", {}).get("as_owner")
        country_fullname = get_country_name(country)

        # Check if whois_date_utc is not None before converting
        if whois_date_utc is not None:
            whois_date = datetime.fromtimestamp(whois_date_utc, tz=timezone.utc)
        else:
            whois_date = None
        
        last_modification_date = datetime.fromtimestamp(last_modification_date_utc, tz=timezone.utc)

        if response.status_code == 200:
            if mal >= 1:
                return 200, "Malicious", whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats
            elif sus >= 1:
                return 200, "Suspicious", whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats
            else:
                return 200, "Clean", whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats
        elif response.status_code == 400:
            return 400, None
        else:
            print(f"IP {ip_address} {response.status_code} gave non 200/400 status code... \n")
            return -1, None

    except requests.exceptions.RequestException as e:
        print("error in exception \n ", e)
        return 400, None

def checkIP(ip_address, api_key):
    status_code, *result = check_ip_virustotal(api_key, ip_address)

    if status_code == 400:
        print("\n 60 sec sleep, Response code: 400\n")
        time.sleep(60)
        return checkIP(ip_address, api_key)
    elif status_code != 200:
        print(f"\n 60 sec sleep, Response code: {status_code}\n")
        time.sleep(60)
        return checkIP(ip_address, api_key)
    else:
        is_malicious, whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats = result
        return is_malicious, whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats

def callAPI(api_key, df, start_index):
    for index in range(start_index - 1, len(df)):
        ip_address = df.at[index, 'IP']
        status = df.at[index, 'Status']
        link = df.at[index, 'Link']

        if is_valid_ip(ip_address):
            if pd.isnull(status and link):
                is_malicious, whois_date, last_modification_date, country_fullname, as_owner, link, last_analysis_stats = checkIP(ip_address, api_key)

                if whois_date is not None:
                    whois_date_unaware = whois_date.astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    whois_date_unaware = None

                last_modification_date_unaware = last_modification_date.astimezone(timezone.utc).replace(tzinfo=None)

                print(f"\n This {ip_address} is {is_malicious}, country: {country_fullname}, owner: {as_owner} \n ")

                df.at[index, 'Status'] = is_malicious
                df.at[index, 'Link'] = link
                df.at[index, 'last_analysis_stats'] = last_analysis_stats
                df.at[index, 'Country'] = country_fullname
                df.at[index, 'whois_date'] = whois_date_unaware
                df.at[index, 'Last_Modification_Date'] = last_modification_date_unaware
                df.at[index, 'AS_Owner'] = as_owner
                # Call the update function after processing each IP
                update_github_file(api_token, repo_owner, repo_name, branch_name, file_path, df)
                df.to_csv(csv_file_path, index=False)

            else:
                pass
                # print(f"{ip_address} has been already scanned!")
        else:
            print(f"{ip_address} is not a valid IP address.")
            df.at[index, 'Status'] = "Not a valid IP address"
            update_github_file(api_token, repo_owner, repo_name, branch_name, file_path, df)
            df.to_csv(csv_file_path, index=False)
            
def get_country_name(country_code):
    country_codes = {
    'AF': 'Afghanistan',
    'AL': 'Albania',
    'DZ': 'Algeria',
    'AD': 'Andorra',
    'AO': 'Angola',
    'AG': 'Antigua and Barbuda',
    'AR': 'Argentina',
    'AM': 'Armenia',
    'AU': 'Australia',
    'AT': 'Austria',
    'AZ': 'Azerbaijan',
    'BS': 'Bahamas',
    'BH': 'Bahrain',
    'BD': 'Bangladesh',
    'BB': 'Barbados',
    'BY': 'Belarus',
    'BE': 'Belgium',
    'BZ': 'Belize',
    'BJ': 'Benin',
    'BM': 'Bermuda',
    'BT': 'Bhutan',
    'BO': 'Bolivia',
    'BA': 'Bosnia and Herzegovina',
    'BW': 'Botswana',
    'BR': 'Brazil',
    'BN': 'Brunei',
    'BG': 'Bulgaria',
    'BF': 'Burkina Faso',
    'MM': 'Burma (Myanmar)',
    'BI': 'Burundi',
    'KH': 'Cambodia',
    'CM': 'Cameroon',
    'CA': 'Canada',
    'CV': 'Cape Verde',
    'KY': 'Cayman Islands',
    'CF': 'Central African Republic',
    'TD': 'Chad',
    'CL': 'Chile',
    'CN': 'China',
    'CX': 'Christmas Island',
    'CC': 'Cocos (Keeling) Islands',
    'CO': 'Colombia',
    'KM': 'Comoros',
    'CG': 'Congo',
    'CK': 'Cook Islands',
    'CR': 'Costa Rica',
    'HR': 'Croatia',
    'CU': 'Cuba',
    'CY': 'Cyprus',
    'CZ': 'Czech Republic',
    'CD': 'Democratic Republic of the Congo',
    'DK': 'Denmark',
    'DG': 'Diego Garcia',
    'DJ': 'Djibouti',
    'DM': 'Dominica',
    'DO': 'Dominican Republic',
    'EC': 'Ecuador',
    'EG': 'Egypt',
    'SV': 'El Salvador',
    'GQ': 'Equatorial Guinea',
    'ER': 'Eritrea',
    'EE': 'Estonia',
    'ET': 'Ethiopia',
    'FK': 'Falkland Islands',
    'FO': 'Faroe Islands',
    'FJ': 'Fiji',
    'FI': 'Finland',
    'FR': 'France',
    'GF': 'French Guiana',
    'PF': 'French Polynesia',
    'GA': 'Gabon',
    'GM': 'Gambia',
    'GE': 'Georgia',
    'DE': 'Germany',
    'GH': 'Ghana',
    'GI': 'Gibraltar',
    'GR': 'Greece',
    'GL': 'Greenland',
    'GD': 'Grenada',
    'GP': 'Guadeloupe',
    'GU': 'Guam',
    'GT': 'Guatemala',
    'GN': 'Guinea',
    'GW': 'Guinea-Bissau',
    'GY': 'Guyana',
    'HT': 'Haiti',
    'VA': 'Holy See (Vatican City)',
    'HN': 'Honduras',
    'HK': 'Hong Kong',
    'HU': 'Hungary',
    'IS': 'Iceland',
    'IN': 'India',
    'ID': 'Indonesia',
    'IR': 'Iran',
    'IQ': 'Iraq',
    'IE': 'Ireland',
    'IM': 'Isle of Man',
    'IL': 'Israel',
    'IT': 'Italy',
    'CI': 'Ivory Coast',
    'JM': 'Jamaica',
    'JP': 'Japan',
    'JE': 'Jersey',
    'JO': 'Jordan',
    'KZ': 'Kazakhstan',
    'KE': 'Kenya',
    'KI': 'Kiribati',
    'KW': 'Kuwait',
    'KG': 'Kyrgyzstan',
    'LA': 'Laos',
    'LV': 'Latvia',
    'LB': 'Lebanon',
    'LS': 'Lesotho',
    'LR': 'Liberia',
    'LY': 'Libya',
    'LI': 'Liechtenstein',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'MO': 'Macau',
    'MK': 'Macedonia',
    'MG': 'Madagascar',
    'MW': 'Malawi',
    'MY': 'Malaysia',
    'MV': 'Maldives',
    'ML': 'Mali',
    'MT': 'Malta',
    'MH': 'Marshall Islands',
    'MQ': 'Martinique',
    'MR': 'Mauritania',
    'MU': 'Mauritius',
    'YT': 'Mayotte',
    'MX': 'Mexico',
    'FM': 'Micronesia',
    'MD': 'Moldova',
    'MC': 'Monaco',
    'MN': 'Mongolia',
    'ME': 'Montenegro',
    'MS': 'Montserrat',
    'MA': 'Morocco',
    'MZ': 'Mozambique',
    'NA': 'Namibia',
    'NR': 'Nauru',
    'NP': 'Nepal',
    'NL': 'Netherlands',
    'AN': 'Netherlands Antilles',
    'NC': 'New Caledonia',
    'NZ': 'New Zealand',
    'NI': 'Nicaragua',
    'NE': 'Niger',
    'NG': 'Nigeria',
    'NU': 'Niue',
    'NF': 'Norfolk Island',
    'KP': 'North Korea',
    'MP': 'Northern Mariana Islands',
    'NO': 'Norway',
    'OM': 'Oman',
    'PK': 'Pakistan',
    'PW': 'Palau',
    'PS': 'Palestine',
    'PA': 'Panama',
    'PG': 'Papua New Guinea',
    'PY': 'Paraguay',
    'PE': 'Peru',
    'PH': 'Philippines',
    'PN': 'Pitcairn Islands',
    'PL': 'Poland',
    'PT': 'Portugal',
    'PR': 'Puerto Rico',
    'QA': 'Qatar',
    'CG': 'Republic of the Congo',
    'RE': 'Reunion Island',
    'RO': 'Romania',
    'RU': 'Russia',
    'RW': 'Rwanda',
    'BL': 'Saint Barthelemy',
    'SH': 'Saint Helena',
    'KN': 'Saint Kitts and Nevis',
    'LC': 'Saint Lucia',
    'MF': 'Saint Martin',
    'PM': 'Saint Pierre and Miquelon',
    'VC': 'Saint Vincent and the Grenadines',
    'WS': 'Samoa',
    'SM': 'San Marino',
    'ST': 'Sao Tome and Principe',
    'SA': 'Saudi Arabia',
    'SN': 'Senegal',
    'RS': 'Serbia',
    'SC': 'Seychelles',
    'SL': 'Sierra Leone',
    'SG': 'Singapore',
    'SX': 'Sint Maarten',
    'SK': 'Slovakia',
    'SI': 'Slovenia',
    'SB': 'Solomon Islands',
    'SO': 'Somalia',
    'ZA': 'South Africa',
    'KR': 'South Korea',
    'SS': 'South Sudan',
    'ES': 'Spain',
    'LK': 'Sri Lanka',
    'SD': 'Sudan',
    'SR': 'Suriname',
    'SJ': 'Svalbard',
    'SZ': 'Swaziland',
    'SE': 'Sweden',
    'CH': 'Switzerland',
    'SY': 'Syria',
    'TW': 'Taiwan',
    'TJ': 'Tajikistan',
    'TZ': 'Tanzania',
    'TH': 'Thailand',
    'TL': 'Timor-Leste (East Timor)',
    'TG': 'Togo',
    'TK': 'Tokelau',
    'TO': 'Tonga',
    'TT': 'Trinidad and Tobago',
    'TN': 'Tunisia',
    'TR': 'Turkey',
    'TM': 'Turkmenistan',
    'TC': 'Turks and Caicos Islands',
    'TV': 'Tuvalu',
    'UG': 'Uganda',
    'UA': 'Ukraine',
    'AE': 'United Arab Emirates',
    'GB': 'United Kingdom',
    'US': 'United States',
    'UY': 'Uruguay',
    'VI': 'US Virgin Islands',
    'UZ': 'Uzbekistan',
    'VU': 'Vanuatu',
    'VE': 'Venezuela',
    'VN': 'Vietnam',
    'WF': 'Wallis and Futuna',
    'EH': 'Western Sahara',
    'YE': 'Yemen',
    'ZM': 'Zambia',
    'ZW': 'Zimbabwe'
    }

    if country_code in country_codes:
        return country_codes[country_code]
    else:
        return country_code
               
               

def main():
    api_key = '504a439e74d6bd4a5c930e268a7ee61153e828ea998736220c2b7bbd8567d88a'
    raw_content_url = 'https://raw.githubusercontent.com/ProSehran/postmantest/main/vir_git.csv'
    df = pd.read_csv(io.StringIO(requests.get(raw_content_url).text))
    
    df['Status'] = df['Status'].astype('object')
    df['Link'] = df['Link'].astype('object')
    df['last_analysis_stats'] = df['last_analysis_stats'].astype('object')
    df['Country'] = df['Country'].astype('object')
    df['whois_date'] = df['whois_date'].astype('object')
    df['Last_Modification_Date'] = df['Last_Modification_Date'].astype('object')
    df['AS_Owner'] = df['AS_Owner'].astype('object')


    # start_index = int(input("\n Enter the starting Sno. from where you want to process IP addresses: "))
    start_index = 1
    callAPI(api_key, df, start_index)

    # Call the update function after processing IPs
    # update_github_file(github_api_token, 'ProSehran', 'postmantest', 'main', csv_file_path, df)


if __name__ == "__main__":
    main()




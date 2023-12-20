#!/bin/bash

# Generate a list of unique packages with exact=true from BlackDuck output data.
generate_package_list() {
  local file=$1
  cat "${file}" | jq -c '.results.components[] |[ .lib, .version ]' | sort | uniq > list.txt
}

# Extract CVE-ID and CVSS vector information from objects that match the package name and version.
extract_cve_and_vector() {
  local file=$1
  local packageName=$2
  local packageVersion=$3
  local output_file="${file}.csv"
  if [ "${packageVersion}" == null ]; then
    cat "${file}" | jq -r -c --arg pn "${packageName}" '.results.components[] | select(.lib == $pn and .version == null ) | .vulns[] | select( .exact == true and .vuln.cve != "") | [.vuln.cve? // empty, .vuln.cvss3_version, .vuln.cvss3_vector, .vuln.cvss2_vector ] ' | sed -e s@]@",\"${packageName}\",null]"@g   >> "${output_file}"
  else
    cat "${file}" | jq -r -c --arg pn "${packageName}" --arg pv "${packageVersion}" '.results.components[] | select(.lib == $pn and .version == $pv ) | .vulns[] | select( .exact == true and .vuln.cve != "") | [.vuln.cve, .vuln.cvss3_version, .vuln.cvss3_vector, .vuln.cvss2_vector ] ' | sed -e s@]@",\"${packageName}\",\"${packageVersion}\"]"@g   >> "${output_file}"
  fi
}

# Create LeanSeeks JSON file by reading each line of the input file and appending severity information.
create_ls_json() {
  local file=$1
  local output_file="${file}_LS.json"
  local number=$(grep -c "CVE-" "${file}.csv")
  local it=1
  echo '[' > "${output_file}"
  while read -r row; do
    local packageName=$(echo "${row}" | jq -r '.[4]' )
    local packageVersion=$(echo "${row}" | jq -r '.[5]' )
    local cveId=$(echo "${row}" | jq -r '.[0]' )
    local cvss3_version=$(echo "${row}" | jq -r '.[1]' )
    local cvss3_vector=$(echo "${row}" | jq -r '.[2]' )
    local cvss2_vector=$(echo "${row}" | jq -r '.[3]' | sed -e s@:/C:@/C:@g)
    echo "----${cveId}----"
    if [ "${cvss3_vector}" == null -o "${cvss3_vector}" == "" ]; then
      local av=$(echo "${cvss2_vector}" | cut -d "/" -f 1 | cut -d ":" -f 2)
      local ac=$(echo "${cvss2_vector}" | cut -d "/" -f 2 | cut -d ":" -f 2)
      local c=$(echo "${cvss2_vector}" | cut -d "/" -f 4 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
      local i=$(echo "${cvss2_vector}" | cut -d "/" -f 5 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
      local a=$(echo "${cvss2_vector}" | cut -d "/" -f 6 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
      local score=$(cvss_calculator -v "${cvss2_vector}" -2 | sed -n 2P | cut -d ":" -f 2 | tr -d " ") 
      if [ "${score}" > "7.0" ]; then
        local severity="high"
      elif [ "${score}" > "4.0" ]; then
        local severity="medium"
      else
        local severity="low"
      fi
    else
      local av=$(echo "${cvss3_vector}" | cut -d "/" -f 1 | cut -d ":" -f 2)
      local ac=$(echo "${cvss3_vector}" | cut -d "/" -f 2 | cut -d ":" -f 2)
      local c=$(echo "${cvss3_vector}" | cut -d "/" -f 6 | cut -d ":" -f 2)
      local i=$(echo "${cvss3_vector}" | cut -d "/" -f 7 | cut -d ":" -f 2)
      local a=$(echo "${cvss3_vector}" | cut -d "/" -f 8 | cut -d ":" -f 2)
      local score=$(cvss_calculator -v "CVSS:${cvss3_version}/${cvss3_vector}" -3 | sed -n 2p | cut -d ":" -f 2 | tr -d " " | cut -d "(" -f 1)
      local severity=$(cvss_calculator -v "CVSS:${cvss3_version}/${cvss3_vector}" -3 | sed -n 2p | cut -d "(" -f 2 | cut -d ")" -f 1)
    fi

    echo "{
      \"cveId\": \"${cveId}\",
      \"packageName\": \"${packageName}\",
      \"packageVersion\": \"${packageVersion}\",
      \"severity\": \"$(echo "${severity}" | tr "[A-Z]" "[a-z]")\",
      \"cvssScore\": \"${score}\",
      \"title\": \"\",
      \"description\": \"\",
      \"link\": \"\",
      \"AV\": \"${av}\",
      \"AC\": \"${ac}\",
      \"C\": \"${c}\",
      \"I\": \"${i}\",
      \"A\": \"${a}\",
      \"hasFix\": \"\",
      \"exploit\": \"\",
      \"publicExploits\": \"\",
      \"published\": \"\",
      \"updated\": \"\",
      \"type\": \"\"" >> "${output_file}"
    if [ "${it}" -eq "${number}" ]; then
      echo "}]" >> "${output_file}"
    else
      echo "}," >> "${output_file}"
    fi
    it=$((it+1))
  done < "${file}.csv"
}

# Create API JSON file.
create_api_json() {
  local file=$1
  local output_file="${file}_LS_API.json"
  echo '[{"id": "'${file}_LS.json'",
    "scanner": 255,
    "payload":' > "${output_file}"
  cat "${file}_LS.json" >> "${output_file}"
  echo '}]' >> "${output_file}"
}

# Main function
main() {
  local file=$1
  generate_package_list "${file}"
  local output_file="${file}.csv"
  while read -r row; do
    local packageName=$(echo "${row}" | jq -r '.[0]')
    local packageVersion=$(echo "${row}" | jq -r '.[1]')
    echo "${packageName} / ${packageVersion}"
    extract_cve_and_vector "${file}" "${packageName}" "${packageVersion}"
  done < list.txt
  create_ls_json "${file}"
  create_api_json "${file}"
  rm list.txt "${file}.csv"
}

main "$@"

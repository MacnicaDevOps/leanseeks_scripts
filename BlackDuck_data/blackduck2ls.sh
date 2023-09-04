#!/bin/bash

file=${1}

# BlackDuckの出力データから有効(exact=true)かつ、ユニークなパッケージのリストを作成する。
echo "パッケージリストの生成"
cat ${file} | jq -c '.results.components[] |[ .lib, .version ]' | sort | uniq > list.txt

# list.txtの中のCVEIDを一行ずつ読み込み、パッケージ名とバージョン一致するオブジェクトを抽出する。
# 該当するオブジェクトから、exact=trueのcve IDとVector情報を抽出する。
echo "パッケージに紐づくCSVとVectorのリストを作成"
while read row; do
    #line="'${row}'"
    packageName=$(echo "${row}" | jq -r '.[0]')
    packageVersion=$(echo "${row}" | jq -r '.[1]')
    echo "${packageName} / ${packageVersion}"
    ## packageNameとpackageVersionが一致するオブジェクトを抽出し、その中のexact=trueのオブジェクトに含まれるCVE-IDとCVSSベクターを抽出する。出力の中にpackageNameとpackageVersionも挿入する。ただし、.vuln.cveが空欄の場合はその行をスキップする。
    if [ ${packageVersion} == null ]; then
      cat ${file} | jq -r -c '.results.components[] | select(.lib == "'${packageName}'" and .version == null ) | .vulns[] | select( .exact == true and .vuln.cve != "") | [.vuln.cve? // empty, .vuln.cvss3_version, .vuln.cvss3_vector, .vuln.cvss2_vector ] ' | sed -e s@]@",\"${packageName}\",null]"@g   >> ${file}.csv
    else
      cat ${file} | jq -r -c '.results.components[] | select(.lib == "'${packageName}'" and .version == "'${packageVersion}'" ) | .vulns[] | select( .exact == true and .vuln.cve != "") | [.vuln.cve, .vuln.cvss3_version, .vuln.cvss3_vector, .vuln.cvss2_vector ] ' | sed -e s@]@",\"${packageName}\",\"${packageVersion}\"]"@g   >> ${file}.csv
    fi
    #cat ${file} | jq -r -c '.results.components[] | select(.lib == "'${packageName}'" and .version == "'${packageVersion}'" ) | .vulns[] | select( .exact == true) | [.vuln.cve, .vuln.cvss3_version, .vuln.cvss3_vector, .vuln.cvss2_vector ]'  >> ${file}.csv
done < list.txt

# ファイルを一行ずつよみながら、中のベクターストリングからセベリティ情報を補完してLeanSeeks用のJSONファイルを作成する。OSVOut.cvsの中のベクターストリングの値は、cvss_calculatorの出力の2行目の出力から()の中にあるCVSSセベリティを抽出する。
it=1
dirname="data"
number=$(cat ${file}.csv | grep -c "CVE-")
echo '[' > "${file}_LS.json"
while read row; do
  packageName=$(echo $row | jq -r '.[4]' )
  packageVersion=$(echo $row | jq -r '.[5]' )
  cveId=$(echo $row | jq -r '.[0]' )
  cvss3_version=$(echo $row | jq -r '.[1]' )
  cvss3_vector=$(echo $row | jq -r '.[2]' )
  cvss2_vector=$(echo $row | jq -r '.[3]' | sed -e s@:/C:@/C:@g)
  echo "----${cveId}----"
  if [ ${cvss3_vector} == null -o ${cvss3_vector} == "" ]; then
    av=$(echo ${cvss2_vector} | cut -d "/" -f 1 | cut -d ":" -f 2)
    ac=$(echo ${cvss2_vector} | cut -d "/" -f 2 | cut -d ":" -f 2)
    c=$(echo ${cvss2_vector} | cut -d "/" -f 4 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
    i=$(echo ${cvss2_vector} | cut -d "/" -f 5 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
    a=$(echo ${cvss2_vector} | cut -d "/" -f 6 | cut -d ":" -f 2| sed -e s@C@H@g | sed -e s@P@L@g)
    score=$(cvss_calculator -v ${cvss2_vector} -2 | sed -n 2P | cut -d ":" -f 2 | tr -d " ") 
    if [ ${score} > "7.0" ]; then
      severity="high"
    elif [ ${score} > "4.0" ]; then
      severity="medium"
    else
      severity="low"
    fi
  else
    av=$(echo ${cvss3_vector} | cut -d "/" -f 1 | cut -d ":" -f 2)
    ac=$(echo ${cvss3_vector} | cut -d "/" -f 2 | cut -d ":" -f 2)
    c=$(echo ${cvss3_vector} | cut -d "/" -f 6 | cut -d ":" -f 2)
    i=$(echo ${cvss3_vector} | cut -d "/" -f 7 | cut -d ":" -f 2)
    a=$(echo ${cvss3_vector} | cut -d "/" -f 8 | cut -d ":" -f 2)
    score=$(cvss_calculator -v "CVSS:"${cvss3_version}"/"${cvss3_vector} -3 | sed -n 2p | cut -d ":" -f 2 | tr -d " " | cut -d "(" -f 1)
    severity=$(cvss_calculator -v "CVSS:"${cvss3_version}"/"${cvss3_vector} -3 | sed -n 2p | cut -d "(" -f 2 | cut -d ")" -f 1)
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
    \"type\": \"\"" >> "${file}_LS.json"
  if [ ${it} -eq ${number} ]; then
    echo "}]" >> "${file}_LS.json"
  else
    echo "}," >> "${file}_LS.json"
  fi
  #echo "${it}/${number}"
  it=$((it+1))
done < ${file}.csv

# API用のJSONファイルを作成する。
echo '[{"id": "'${file}_LS.json'",
    "scanner": 255,
    "payload":' > "${file}_LS_API.json"
cat ${file}_LS.json >> "${file}_LS_API.json"
echo '}]' >> "${file}_LS_API.json"

# 作業ファイルの削除
rm list.txt
rm ${file}.csv

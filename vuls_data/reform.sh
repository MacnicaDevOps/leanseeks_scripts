#!/bin/bash

## file check
if [ $# -lt 1 ]; then
  echo "ファイル名を指定してください"
  exit 1
fi

## 変数指定
filename=${1}
dirname=$(echo ${1} | cut -d . -f 1)
it=1

## CVEの一覧を作る
mkdir -p ${dirname}
cat ${filename} | jq -r '.scannedCves | keys | flatten | unique | .[] ' > ${dirname}/cve_list.txt
## CVE数をカウント
number=$(cat ${dirname}/cve_list.txt | grep -c "CVE-")

## データから必要な情報を抜き出してアレイにする
echo '[' > ${dirname}/vuln_data.json
while read row; do
  data=$(cat ${filename} | jq -r '.scannedCves."'${row}'"')
  source=$(echo ${data} | tr -d "[:cntrl:]" | jq ".cveContents | keys[0]")
    if [ $(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Score") != "0" ]; then
      severity=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Severity")
      score=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Score")
      title=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].title" | sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      description=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].summary" | sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      vector=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Vector")
      AV=$(echo ${vector} | tr -d "[:cntrl:]" | cut -d / -f 2 | sed -e "s/AV://g")
      AC=$(echo ${vector} | cut -d / -f 3 | sed -e "s/AC://g")
      C=$(echo ${vector} | cut -d / -f 7 | sed -e "s/C://g")
      I=$(echo ${vector} | cut -d / -f 8 | sed -e "s/I://g")
      A=$(echo ${vector} | cut -d / -f 9 | sed -e "s/A://g")
    elif [ $(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss2Score") != "0" ]; then
      severity=$(echo ${data} | jq -r ".cveContents.${source}[0].cvss2Severity")
      score=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss2Score")
      title=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].title"| sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      description=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].summary"| sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      vector=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss2Vector")
      AV=$(echo ${vector} | cut -d / -f 1 | sed -e "s/AV://g")
      AC=$(echo ${vector} | cut -d / -f 2 | sed -e "s/AC://g")
        if [ ${AC} == "M" ]; then AC="H"; fi
      C=$(echo ${vector} | cut -d / -f 4 | sed -e "s/C://g")
        if [ ${C} == "C" ]; then C="H"; fi
        if [ ${C} == "P" ]; then C="L"; fi
      I=$(echo ${vector} | cut -d / -f 5 | sed -e "s/I://g")
        if [ ${I} == "C" ]; then I="H"; fi
        if [ ${I} == "P" ]; then I="L"; fi
      A=$(echo ${vector} | cut -d / -f 6 | sed -e "s/A://g")
        if [ ${A} == "C" ]; then A="H"; fi
        if [ ${A} == "P" ]; then A="L"; fi
    else
      source=$(echo ${data} | tr -d "[:cntrl:]" | jq ".cveContents | keys[1]")
      severity=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Severity")
      score=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Score")
      title=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].title"| sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      description=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].summary"| sed s@\"@\'@g | tr -d '\n' | tr -d '\')
      vector=$(echo ${data} | tr -d "[:cntrl:]" | jq -r ".cveContents.${source}[0].cvss3Vector")
      AV=$(echo ${vector} | tr -d "[:cntrl:]" | cut -d / -f 2 | sed -e "s/AV://g")
      AC=$(echo ${vector} | cut -d / -f 3 | sed -e "s/AC://g")
      C=$(echo ${vector} | cut -d / -f 7 | sed -e "s/C://g")
      I=$(echo ${vector} | cut -d / -f 8 | sed -e "s/I://g")
      A=$(echo ${vector} | cut -d / -f 9 | sed -e "s/A://g")
    fi

#パッケージ名とバージョンを取得
    if [ $(echo ${data} | jq -r ".cpeURIs[0]") != null ]; then
      packageName=$(echo ${data} | tr -d "[:cntrl:]" | jq -r '.cpeURIs[0]' | cut -d : -f 4)
      packageVersion=$(echo ${data} | tr -d "[:cntrl:]" | jq -r '.cpeURIs[0]' | cut -d : -f 5)
    else
      packageName=($(echo ${data} | tr -d "[:cntrl:]" | jq -r '.affectedPackages[0].name' | xargs| sed 's/ /,/g'))
      packageVersion="N/A"
    fi

# エクスプロイトデータの取得
# もし${data} | jq -r ".exploits"がnullでなければexploit=1とする。なければexploit=0とする。
    if [ "$(echo ${data} | tr -d '[:cntrl:]' | jq -r '.exploits')" != null ]; then
      exploit="1"
      pubExp=$(echo ${data} | tr -d "[:cntrl:]" | jq -c "[.exploits[].url] | @csv")
    else
      exploit="0"
      pubExp='""'
    fi


echo "cveId=${row}"

## JSONの組み立て
echo '{
    "cveId": "'"${row}"'",
    "packageName": "'"${packageName}"'",
    "packageVersion": "'"${packageVersion}"'",
    "severity": "'$(echo "${severity}" | tr "[A-Z]" "[a-z]")'",
    "cvssScore": "'"${score}"'",
    "title": "'"${title}"'",
    "description": "'"${description}"'",
    "link": "",
    "AV": "'"${AV}"'",
    "AC": "'"${AC}"'",
    "C": "'"${C}"'",
    "I": "'"${I}"'",
    "A": "'"${A}"'",
    "hasFix": "",
    "exploit": "'"${exploit}"'",
    "publicExploits": '"${pubExp}"',
    "published": "",
    "updated": "",
    "type": ""' >> ${dirname}/vuln_data.json
  if [ ${it} -eq ${number} ]; then
    echo "}]" >> ${dirname}/vuln_data.json
    #echo ${vuln_data} | jq > "${dirname}_LS.json"
  else
    echo "}," >> ${dirname}/vuln_data.json
  fi
  echo "${it}/${number}"
  it=$((it+1))

done < ${dirname}/cve_list.txt

# CVEリストの削除
rm ${dirname}/cve_list.txt

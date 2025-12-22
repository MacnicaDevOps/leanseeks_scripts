#!/bin/bash
filename=yocto.json

#create list of packages
cat ${filename} | jq -r -c ".package[] |[ .name, .version ]" > packages.txt

# packages.txtを1行づつ読み込みながら、${filename}から.packages[].nameと.versionが一致する配列を抽出
echo '[' > LS_data_temp.json
while read row; do
  package=$(echo ${row} | jq ".[0]")
  version=$(echo ${row} | jq ".[1]")
  cves=$(cat ${filename} | jq ".package[] | select( .name == ${package} and .version == ${version} )" | jq -c ".issue[] |[ .id , .vectorString ]")
  echo ${cves} | jq -c > lines.txt

  if [ -n "${cves}" ]; then 
    while read line
    do
    id=$(echo ${line} | jq ".[0]")
    vector=$(echo ${line} | jq -r ".[1]")

    if [[ \"${vector}\" == *"UNKNOWN"* ]]; then
      AV=""
      AC=""
      C=""
      I=""
      A=""
      severity=""
      score=""
    elif [[ \"${vector}\" == *"CVSS:3"* ]]; then
      # vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
      AV=$(echo \"${vector}\" | cut -d "/" -f2 | cut -d ":" -f2 | sed -e 's/"//g')
      AC=$(echo \"${vector}\" | cut -d "/" -f3 | cut -d ":" -f2 )
      C=$(echo \"${vector}\" | cut -d "/" -f7 | cut -d ":" -f2 )
      I=$(echo \"${vector}\" | cut -d "/" -f8 | cut -d ":" -f2 )
      A=$(echo \"${vector}\" | cut -d "/" -f9 | cut -d ":" -f2 | sed -e 's/"//g')
      cvss=$(cvss_calculator -v ${vector} | sed -n 2P )
      score=$(echo ${cvss} | cut -d " " -f14)
      severity=$(echo ${cvss}  | cut -d "(" -f2 | cut -d ")" -f1 | tr "[A-Z]" "[a-z]")
    else
      # vector="AV:L/AC:L/Au:N/C:C/I:C/A:C"
      AV=$(echo \"${vector}\" | cut -d / -f 1 | sed -e "s/AV://g" | sed -e 's/"//g')
      AC=$(echo \"${vector}\" | cut -d / -f 2 | sed -e "s/AC://g")
        if [ ${AC} == "M" ]; then AC="H"; fi
      C=$(echo \"${vector}\" | cut -d / -f 4 | sed -e "s/C://g")
        if [ ${C} == "C" ]; then C="H"; fi
        if [ ${C} == "P" ]; then C="L"; fi
      I=$(echo \"${vector}\" | cut -d / -f 5 | sed -e "s/I://g")
        if [ ${I} == "C" ]; then I="H"; fi
        if [ ${I} == "P" ]; then I="L"; fi
      A=$(echo \"${vector}\" | cut -d / -f 6 | sed -e "s/A://g" | sed -e 's/"//g')
        if [ ${A} == "C" ]; then A="H"; fi
        if [ ${A} == "P" ]; then A="L"; fi  
      score=$(cvss_calculator -v ${vector} -2 | sed -n 2P | cut -d " " -f14)
      score2=$(echo ${score} | sed -e 's/\.//g')
      if [ "$(echo $((score2 >= 70| bc)))" == "1" ]; then severity="high"
      elif [ "$(echo $((score2 >= 40| bc)))" == "1" ]; then severity="medium"
      else severity="low"
      fi
    fi

    ## JSONの組み立て
    echo "{
      \"cveId\": ${id},
      \"packageName\": ${package},
      \"packageVersion\": ${version},
      \"severity\": \"${severity}\",
      \"cvssScore\": \"${score}\",
      \"title\": \"\",
      \"description\": \"\",
      \"link\": \"\",
      \"AV\": \"${AV}\",
      \"AC\": \"${AC}\",
      \"C\": \"${C}\",
      \"I\": \"${I}\",
      \"A\": \"${A}\",
      \"hasFix\": \"\",
      \"exploit\": \"\",
      \"publicExploits\": \"\",
      \"published\": \"\",
      \"updated\": \"\",
      \"type\": \"\"
      }," >> LS_data_temp.json
    done < lines.txt
  fi

done < packages.txt

echo '{}]' >> LS_data_temp.json
cat LS_data_temp.json | jq -c | sed -e 's@,{}]@]@g' | jq  > LS_data.json

rm -f lines.txt packages.txt LS_data_temp.json

#!/bin/bash

## 以下に変数を指定します。CIツールの環境変数からの読み込みができる場合はツールの仕様にあわせて指定してください。
#image="prisma-scan:latest"
#pc_user=""
#pc_pass=""
#pc_user=""
#ls_token=""
#ls_url="https://leanseeks.macnica.co.jp"
#ua="user-agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
#app_name="prisma-scan"
#app_priority="H"
#scanner="0"

# ワークディレクトリを作成する
mkdir work
#Prisma Cloudに対象イメージの脆弱性情報を問い合わせる
curl -u "${pc_user}:${pc_pass}" -H "Content-Type: application/json" "${pc_url}/api/v1/scans?search=${image}" | jq -r '[ .[].entityInfo ]' > "work/ci_scan.json"

# LeanSeeks用のアップロードデータを生成する
echo "------- LeanSeeksのアップロードデータを生成中"
echo '[{"id": "ci_scan.json","scanner": 0,"payload":' > "work/vuln_data.json"
cat "work/ci_scan.json" >> "work/vuln_data.json"
echo "}]" >> "work/vuln_data.json"

# LeanSeeksのアップロード情報を取得し、URLとTokenを変数に入れる
echo "------- LeanSeeksのアップロードURLを情報取得中"
cred=$(curl -X "GET" "${ls_url}/api/vulnerability-scan-results/upload-destination" -H "accept: application/json" -H "Accept-Language: ja" -H "Authorization: Bearer ${ls_token}" -H "${ua}")
s3_url=$(echo "${cred}" | jq -r ".uploadDestination.url")
s3_jwt=$(echo "${cred}" | jq -r ".uploadDestination.key")

# データをLeanSeeksにアップロードする
echo "------- データをLeanSeeksにアップロード中"
curl -X 'PUT' "${s3_url}" --data-binary @work/vuln_data.json 

# トリアージ用のパラメーターをparams.csvからmapping.jqを用いて生成する
echo "------- トリアージリクエストパラメーターの準備中"

param="{ \"application_name\": \"${app_name}\", \"importance\": \"${app_priority}\", \"is_template\": false, \"pods\":"
param+=$(jq -R -s -f mapping.jq params.csv | jq -r -c '[.[] |select(.pod_name != null and .is_root != "is_root" )]'| sed -e 's/"¥r"//g')"}"
echo ${param} | sed 's/"TRUE"/true/g' | sed -e 's/"FALSE"/false/g' > "work/param.json"

# トリアージリクエストを実行する
echo "------- トリアージリクエスト実行中"
curl -X 'POST' "${ls_url}/api/triage-requests" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Vulnerability-Scan-Result-Resource-Id: ${s3_jwt}" -H "Authorization: Bearer ${ls_token}" -H 'Content-Type: application/json' -H "${ua}" -d @work/param.json > "work/result.json"
triage_id=$(cat work/result.json | jq -r ".triage.triageId")
cat work/result.json | jq

# トリアージ結果を10秒間隔で取得する。成功するまで繰り返す。
i=1
while true
  do
              echo "---- 処理待ち_${i}"
              curl -X 'GET' "${ls_url}/api/triage-results/${triage_id}/status" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Authorization: Bearer ${ls_token}" -H 'Content-Type: application/json' -H "$ua" -o work/t_result.json
              status=$(cat work/t_result.json | jq -r ".triage.status")
              echo "statusは「${status}」です"
              if [ "${status}" == "成功" ]; then
                cat work/t_result.json | jq -r ".triage"
                if [ $(cat work/t_result.json | jq -r ".triage.level5VulnerabilityCounts") != 0 ]; then
                  echo "緊急対処が必要な脆弱性が見つかりました！"
                  echo "レベル5 緊急対処: "$(cat work/t_result.json | jq -r ".triage.level5VulnerabilityCounts")"件"
                  exit 1
                elif [ $(cat work/t_result.json | jq -r ".triage.level4VulnerabilityCounts") != 0 ]; then
                  echo "緊急対処が推奨される脆弱性が見つかりました！"
                  echo "レベル4 緊急対処推奨: "$(cat work/t_result.json | jq -r ".triage.level4VulnerabilityCounts")"件"
                  exit 1
                elif [ $(cat work/t_result.json | jq -r ".triage.level3VulnerabilityCounts") != 0 ]; then
                  echo "対処計画が必要な脆弱性が見つかりましたが、緊急性が低いためパイプラインを継続します"
                  echo "レベル3 対処計画: "$(cat work/t_result.json | jq -r ".triage.level3VulnerabilityCounts")"件"
                  rm -rf work
                  exit 0
                elif [ $(cat work/t_result.json | jq -r ".triage.level2VulnerabilityCounts") != 0 ]; then
                  echo "対処計画が推奨される脆弱性が見つかりましたが、緊急性が低いためパイプラインを継続します"
                  echo "レベル2 対処計画推奨: "$(cat work/t_result.json | jq -r ".triage.level2VulnerabilityCounts")"件"
                  rm -rf work
                  exit 0
                else
                  echo "緊急性のある脆弱性が検知されなかったため、パイプラインを継続します"
                  rm -rf work
                  exit 0
                fi
              elif [ "${status}" == null ]; then
                echo "トリアージリクエストが失敗しました。"
                cat work/t_result.json | jq
                exit 1
              fi
              sleep 10
              i=$((i+1))
  done


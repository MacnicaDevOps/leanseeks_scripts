#!/bin/bash

triage_id=$1

source env.txt
#ls_token=""
#ls_url="https://leanseeks-stg.macnica.co.jp"
#ua="Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"

# Working Directoryの作成
mkdir -p work

# トリアージ結果を取得する
curl -X 'GET' "${ls_url}/api/triage-results/${triage_id}/" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Authorization: Bearer ${ls_token}" -H 'Content-Type: application/json' -H "${ua}" | jq > "work/result_temp.json"

# トリアージの属性情報のCSV出力
appname=$(cat work/result_temp.json | jq -r ".triageRequest.a.an")
echo '"アセットID","アセット名","インターネット接続","root","Privileged","待受ポート","機密性リスク","完全性リスク","可用性リスク","スキャナID","ファイル名","トリアージ実行日時"' > "work/${appname}_${triage_id}_properties.csv"
cat work/result_temp.json| jq -r " .triageRequest.a.p[] |[ .pid, .pn, .iic, .ir, .ip, .ipo, .c, .i, .a, .s, .sri, .srua  ] |@csv" >> "work/${appname}_${triage_id}_properties.csv"
nkf --oc=UTF-8-BOM "work/${appname}_${triage_id}_properties.csv" > "work/${appname}_${triage_id}_properties_utf8bom.csv"

# トリアージの脆弱性情報のCSV出力
echo '"アセットID","CVE ID","パッケージ名","パッケージバージョン","セベリティ","CVSSスコア","CVEタイトル","攻撃元区分(AV)","攻撃の複雑さ(AC)","FIXの有無","エクスプロイト状況","公開日","更新日","攻撃の種類","アプリケーションリスク","判定スコア","判定結果","タグ"' > "work/${appname}_${triage_id}_vulnerabilities.csv"
cat work/result_temp.json| jq -r ".cves[] |[ .pid, .cve, .pn, .pv, .s, .cs, .ct, .av, .ac, .if, .ecm, .cp, .cu, .at, .ar, .ps, .pl, .tg[].tn  ] |@csv" >> "work/${appname}_${triage_id}_vulnerabilities.csv"
nkf --oc=UTF-8-BOM "work/${appname}_${triage_id}_vulnerabilities.csv" > "work/${appname}_${triage_id}_vulnerabilities_utf8bom.csv"

# 一時ファイルの削除
rm work/result_temp.json

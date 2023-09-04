#!/bin/bash

triage_id=$1

ls_token=""
ls_url="https://leanseeks.macnica.co.jp"
ua="Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"

# トリアージ結果を取得する
curl -X 'GET' "${ls_url}/api/triage-results/${triage_id}/" -H 'accept: application/json' -H 'Accept-Language: ja' -H "Authorization: Bearer ${ls_token}" -H 'Content-Type: application/json' -H "$ua" | jq > result_temp.json

# トリアージの属性情報のCSV出力
appname=$(cat result_temp.json | jq -r ".triageRequest.a.an")
echo '"インスタンスID","インスタンス名","インターネット接続","root","privileged","待受ポート","機密性リスク","完全性リスク","可用性リスク","スキャナID","ファイル名","トリアージ実行日時"' > "${appname}_${triage_id}_properties.csv"
cat result_temp.json| jq -r " .triageRequest.a.p[] |[ .pid, .pn, .iic, .ir, .ip, .ipo, .c, .i, .a, .s, .sri, .srua  ] |@csv" >> "${appname}_${triage_id}_properties.csv"

# トリアージの脆弱性情報のCSV出力
echo '"インスタンスID","CVE-ID","パッケージ名","パッケージバージョン","セベリティ","CVSSスコア","タイトル","攻撃元区分","攻撃の複雑性","FIXの有無","エクスプロイト状況","公開日","更新日","攻撃の種類","アプリケーションリスク","判定スコア","判定結果","タグ"' > "${appname}_${triage_id}_vulnerabilities.csv"
cat result_temp.json| jq -r ".cves[] |[ .pid, .cve, .pn, .pv, .s, .cs, .ct, .av, .ac, .if, .ecm, .cp, .cu, .at, .ar, .ps, .pl, .tg[].tn  ] |@csv" >> "${appname}_${triage_id}_vulnerabilities.csv"

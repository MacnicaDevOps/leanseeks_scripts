## トリアージIDを指定して結果をCSV出力します。

#### 利用方法

`./csv_export.sh <トリアージID>`

※ <トリアージID>は、「トリアージ結果　レポート」画面を表示したときのURLの末尾にある数値です。</br>
例: https://leanseeks.macnica.co.jp/triage-results/12345 </br>
上記のケースでは「12345」がトリアージIDです。</br>
このトリアージIDの結果を出力する場合は、以下のように実行します。

`./csv_export.sh 12345`

#### 事前準備

1. スクリプトの5行目のls_tokenにご自身のトークンを代入します。</br>
   `ls_token="AbcDEfg12345・・・・"`
2. スクリプトに実行権限を付与します。</br>
   `chmod +x csv_export.sh`
3. スクリプト実行環境でjqが使えることを確認します。ない場合はインストールします。</br>
   https://jqlang.github.io/jq/

#### 出力結果

本スクリプトの実行により、ファイルが2つ生成されます。

1. <アプリケーション名>_<トリアージID>_properties.csv </br>
トリアージ実行時に指定した属性情報を出力します。

出力例:

|インスタンスID|インスタンス名|インターネット接続|root|privileged|待受ポート|機密性リスク|完全性リスク|可用性リスク|スキャナID|ファイル名|トリアージ実行日時|
|----|----|----|----|----|----|----|----|----|----|----|----|
|10005|インスタンス01|true|true|false|true|H|H|H|255|instance_1.json|2023/09/01 19:30:03|
|10006|インスタンス02|false|false|false|true|M|H|M|255|instance_2.json|2023/09/01 19:30:03|


2. <アプリケーション名>_<トリアージID>_vulnerabilities.csv </br>
トリアージ結果の一覧を出力します。

出力例:

|インスタンスID|CVE-ID|パッケージ名|パッケージバージョン|セベリティ|CVSSスコア|タイトル|攻撃元区分|攻撃の複雑性|FIXの有無|エクスプロイト状況|公開日|更新日|攻撃の種類|アプリケーションリスク|判定スコア|判定結果|タグ|
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
|10005|CVE-2019-1981|linux|5.10.84-1|critical|9.13|CISCO:20190816 Cisco Firepower Threat Defense Software NULL Character Obfuscation Detection Bypass Vulnerability|N|L|true|P|2019/11/05|2020/10/16|DOS|H|185.6|3|ignore|
|10006|CVE-2019-0221|Apache Tomcat|9.0.19|critical|6.1|Cross-site scripting|N|L|true|P|2019/05/30|2021/11/25||H|191|3|

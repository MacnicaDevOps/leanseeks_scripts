## BlackDuckのJSONファイルを読み込んでLeanSeeks用のファイルを生成する。

#### 利用方法

`./blackduck2ls.sh <BlackDuckからエクスポートした脆弱性データのJSONファイル>`

例:

`./blackduck2ls.sh blackduck_output.json`

#### 事前準備

1. スクリプトに実行権限を付与します。</br>
   `chmod +x blackduck2ls.sh`

#### 出力結果

1. <BlackDuckからエクスポートした脆弱性データのJSONファイル>_LS.json </br>
LeanSeeksのGUIでトリアージを行う際、スキャナに「汎用フォーマット」を指定の上、こちらのファイルをアップロードします。

2. <BlackDuckからエクスポートした脆弱性データのJSONファイル>_LS_API.json </br>
LeanSeeksのAPIでトリアージを行う際、S3にアップロードするファイルがこちらになります。 </br>
トリアージ実行のAPIでPOSTするデータの"scan_result_id"は、本ファイルの"id"の値と同じになるようにご指定ください。

# Prisma Cloudのレジストリスキャン結果取得によるトリアージテスト

### 概要
triage_registry.shを実行すると、Prisma Cloudからレジストリスキャン結果を取得し、そのデータを用いてトリアージをリクエストします。

```
./triage_registry.sh
```
本スクリプトではPrisma Cloudでスキャンされたレジストリのすべてのイメージに対するトリアージを行います。
※ Prisma Cloudにはレジストリのスキャン結果があることが前提です。

事前にトリアージ対象のイメージのアセット情報をinstance_param.csvに定義します。
csvファイルのscan_result_idのカラムには、リポジトリ名とタグを含むイメージ名を記載してください。
レジストリから取得したデータがcsvに記載されていない場合、アセット情報に自動でデフォルト値を代入します。
デフォルト値は、triage_registry.shの中で定義されているdefault_paramです。

トリアージ処理の実行中はワーキングディレクトリ(work)が生成されます。
生成されたワーキングディレクトリは、トリアージの成功に伴って削除されますが、失敗の場合は削除されません。（トリアージに利用する各種データが入っているため、失敗の原因を調査する際に利用することを想定しています）

### 各種ファイルの概要

|  ファイル名  |  概要  |
| ---- | ---- |
|  triage_registry.sh  |  Prisma Cloudからのレジストリスキャン結果の取得とトリアージ処理を実行するファイル  |
|  instance_param.csv  |  トリアージ対象のアセット情報を定義するファイル  |
|  mapping.jq  |  instance_param.csvをJSONに変換する際のマッピングファイル  |

### triage_request.shに記載するパラメーター
ファイルの上部にある各変数に必要な値を代入するか、該当の変数名をCIの環境変数として保存します。

|  ファイル名  |  概要  |
| ---- | ---- |
| image | Prisma Cloudから脆弱性情報を取得する対象のイメージ名を指定します |
| pc_user | Prisma CloudにAPIアクセスする際のユーザー名を指定します |
| pc_pass | Prisma CloudにAPIアクセスする際のパスワードを指定します |
| pc_url | Prisma CloudにAPIアクセスする際のベースURLを指定します |
| ls_token | LeanSeeksにAPIアクセスする際のtokenを指定します |
| ls_url | LeanSeeksにAPIアクセスする際のURLを指定します |
| ua | LeanSeeksにAPIアクセスする際のUser-Agentを指定します(WAFのチェックが有るため) |
| app_name | トリアージするアセットグループ(アプリケーション)の名前を指定します |
| app_priority | トリアージするアセットグループ(アプリケーション)の重要度を指定します |
| scanner | prisma cloudのID (0)を指定します |
| default_param | instance_param.csvで該当イメージが見つからない場合に代入するアセット情報のデフォルト値です |
# Prisma Cloudのスキャン結果取得によるトリアージテスト

### 概要
triage_request.shを実行すると、image変数に指定されたイメージのスキャン結果をPrisma Cloudから取得し、そのデータを用いてトリアージをリクエストします。

```
./triage_request.sh
```
本スクリプトではスタティックに指定したイメージ名に対するトリアージを行います。
※ Prisma Cloudには予め該当するイメージ名のスキャン結果があることが前提です。
対象のイメージの環境情報はinstance_param.csvに定義します。

トリアージ処理の実行中はワーキングディレクトリ(work)が生成されます。
生成されたワーキングディレクトリは、トリアージの成功に伴って削除されますが、失敗の場合は削除されません。（トリアージに利用する各種データが入っているため、失敗の原因を調査する際に利用することを想定しています）

### 各種ファイルの概要

|  ファイル名  |  概要  |
| ---- | ---- |
|  triage_request.sh  |  トリアージ処理を実行するファイル  |
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
| scanner | prisma cloudのID (0)を指定医します |
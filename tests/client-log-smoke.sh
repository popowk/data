#!/usr/bin/env bash
# Sourced by api-smoke.sh before the admin session fixture is removed.
set -euo pipefail
LOG_HTML=$(mktemp)
trap 'rm -f "$LOG_HTML"' RETURN
php -r '
require "app/core.php";
$id=(int)sql("SELECT id FROM phonehub_users WHERE username=?",["ci_open_plan_user"])->fetchColumn();
if (!$id) exit(2);
$stmt=db()->prepare("INSERT INTO phonehub_client_logs(user_id,device_id,level,event,message,created_at) VALUES(?,?,?,?,?,UTC_TIMESTAMP())");
for ($i=0;$i<113;$i++) {
    $stmt->execute([$id,str_repeat("c",64),"error","ci.test","CI_LOG_PAGE_TEST_".sprintf("%03d",$i)]);
}
$stmt->execute([$id,str_repeat("c",64),"info","ci.test","CI_LOG_PAGE_TEST_NON_ERROR_SHOULD_NOT_MATCH"]);
$stmt->execute([$id,str_repeat("c",64),"error","CI_LOG_EVENT_TARGET","event-only sentinel"]);
$stmt->execute([$id,str_repeat("c",64),"info","CI_LOG_EVENT_TARGET","an info log should not be an error search result"]);
'
log_page() {
  local mode="$1" keyword="$2" page="$3"
  curl -fsS -b "$adminCookies" -G 'http://127.0.0.1:18765/index.php' \
    --data-urlencode 'view=client_logs' --data-urlencode "search_by=$mode" \
    --data-urlencode "q=$keyword" --data-urlencode "page=$page" -o "$LOG_HTML"
}
check_log_page() {
  local expected="$1" current="$2" total="$3"
  EXPECTED_ROWS="$expected" EXPECTED_PAGE="$current" EXPECTED_TOTAL="$total" LOG_HTML="$LOG_HTML" python3 - <<'PY'
import os,re,html
s=open(os.environ["LOG_HTML"],encoding="utf-8").read()
body=re.search(r'<tbody>(.*?)</tbody>',s,re.S)
assert body is not None,"log results table missing"
rows=re.findall(r'<tr\b',body.group(1))
assert len(rows)==int(os.environ["EXPECTED_ROWS"]),(len(rows),os.environ["EXPECTED_ROWS"])
assert "匹配 "+os.environ["EXPECTED_TOTAL"]+" 条" in html.unescape(s), "bad count"
assert "第 "+os.environ["EXPECTED_PAGE"]+" / " in html.unescape(s),"bad page indicator"
PY
}
log_page all CI_LOG_PAGE_TEST 1
check_log_page 50 1 3
grep -q 'page=2' "$LOG_HTML"
grep -q 'search_by=all' "$LOG_HTML"
log_page all CI_LOG_PAGE_TEST 2
check_log_page 50 2 3
grep -q 'page=3' "$LOG_HTML"
log_page all CI_LOG_PAGE_TEST 3
check_log_page 13 3 3
log_page all CI_LOG_PAGE_TEST 900
check_log_page 13 3 3
log_page error CI_LOG_PAGE_TEST 1
check_log_page 50 1 3
grep -q 'value="CI_LOG_PAGE_TEST"' "$LOG_HTML"
log_page error CI_LOG_EVENT_TARGET 1
check_log_page 1 1 1
grep -q 'event-only sentinel' "$LOG_HTML"
if grep -q 'an info log should not be an error' "$LOG_HTML"; then exit 11;fi
log_page username ci_open_plan_user 1
grep -q 'ci_open_plan_user' "$LOG_HTML"
grep -q 'name="search_by"' "$LOG_HTML"
log_page username nonexistent_ci_log_username 1
check_log_page 0 1 1
grep -q '没有符合条件的日志' "$LOG_HTML"
# Invalid pagination is clamped to the first page, and HTML is escaped.
log_page all CI_LOG_PAGE_TEST -5
check_log_page 50 1 3
log_page all '<script>alert(1)</script>' 1
if grep -Fq '<script>alert(1)</script>' "$LOG_HTML"; then exit 12; fi
grep -q '&lt;script&gt;' "$LOG_HTML"
echo 'PASS: client logs 50/page, scoped username/error lookup, escaped LIKE, valid pagination and XSS-safe output'

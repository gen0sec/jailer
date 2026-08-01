#!/bin/bash
# Acceptance test: can a jailer policy jail k8s pods without naming a
# container id? Enrolls the static kubepods.slice and asserts the rule bites
# both immediately and after the pod is recreated.
#
# Run on the k3s node.
set -uo pipefail
export PATH=/opt/bin:$PATH KUBECONFIG=/etc/rancher/k3s/k3s.yaml
PASS=0; FAIL=0
check() { # check <label> <expected ALLOWED|DENIED> <actual>
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; PASS=$((PASS+1))
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}
# A pod that cannot start also cannot connect, and scoring that as DENIED
# turns a broken cluster into a passing test. Assert the pod is actually
# running, and distinguish a failed exec from a refused connection.
require_running() {
  local phase ready
  phase=$(kubectl get pod victim -o jsonpath='{.status.phase}' 2>/dev/null)
  ready=$(kubectl get pod victim -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)
  [ "$phase" = Running ] && [ "$ready" = true ]
}
probe() { # pod -> node:9999
  if ! require_running; then echo "POD-NOT-RUNNING"; return; fi
  local out rc
  out=$(kubectl exec victim -- nc -w3 10.0.2.15 9999 </dev/null 2>&1); rc=$?
  if [ $rc -eq 0 ]; then echo ALLOWED
  elif echo "$out" | grep -qiE "error from server|unable to upgrade|container not found|not running"; then
    echo "EXEC-FAILED"
  else echo DENIED; fi
}
node_probe() { nc -w3 10.0.2.15 9999 </dev/null >/dev/null 2>&1 && echo ALLOWED || echo DENIED; }

python3 - <<'PY'
import json
p='/etc/bpfjailer/policy.json'; d=json.load(open(p))
d['roles']['k8s']={'id':30,'name':'k8s',
 'flags':{'allow_file_access':True,'allow_network':True,'allow_exec':True,
          'require_signed_binary':False,'allow_setuid':True,'allow_ptrace':True},
 'file_paths':[],'network_rules':[],'execution_rules':[],'require_signed_binary':False,
 'domain_rules':[],
 'ip_rules':[{'cidr':'10.0.2.15/32','direction':'connect','allow':False}]}
d['exec_enrollments']=[]
# The whole point: name only the static slice, never a container id.
d['cgroup_enrollments']=[{'cgroup_path':'/sys/fs/cgroup/kubepods.slice','pod_id':7001,'role':'k8s'}]
json.dump(d,open(p,'w'),indent=2)
PY
rm -rf /sys/fs/bpf/bpfjailer && systemctl restart bpfjailer-bootstrap && sleep 3
[ "$(systemctl is-active bpfjailer-bootstrap)" = active ] \
  && echo "  PASS  bootstrap accepts a kubepods.slice enrollment" && PASS=$((PASS+1)) \
  || { echo "  FAIL  bootstrap did not start"; FAIL=$((FAIL+1)); }

check "pod is jailed via the node-wide slice"      DENIED  "$(probe)"
check "node processes are unaffected"              ALLOWED "$(node_probe)"

kubectl delete pod victim --wait=true >/dev/null 2>&1
cat <<'YAML' | kubectl apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Pod
metadata: {name: victim}
spec:
  containers:
  - {name: shell, image: busybox:1.36, command: ['sh','-c','while true; do sleep 5; done']}
YAML
kubectl wait --for=condition=Ready pod/victim --timeout=180s >/dev/null 2>&1
require_running \
  && { echo "  PASS  pod actually starts under the enrollment"; PASS=$((PASS+1)); } \
  || { echo "  FAIL  pod did not start under the enrollment"; FAIL=$((FAIL+1)); }
check "enforcement survives pod recreation"        DENIED  "$(probe)"

echo "  ---- $PASS passed, $FAIL failed ----"
[ "$FAIL" -eq 0 ]

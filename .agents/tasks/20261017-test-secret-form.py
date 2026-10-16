"""One bounded source build/integration run; no real secrets or live services."""
import json,subprocess,time,os
from pathlib import Path
root=Path(__file__).resolve().parents[2]
area=root/'.tmp/20261017-form';area.mkdir(parents=True,exist_ok=True)
available=int(next(x.split()[1]for x in Path('/proc/meminfo').read_text().splitlines()if x.startswith('MemAvailable:')))*1024
assert available>17*1024**3,'insufficient host reserve'
name='sss-form-check-'+str(time.time_ns());start=time.monotonic();cid=None
try:
 cid=subprocess.check_output(['docker','run','-d','-i','--name',name,'--memory=1g','--memory-swap=1g','--cpus=2','--pids-limit=128','--network=none','--tmpfs','/tmp:rw,size=128m','-v',str(root)+':/app','-w','/app','node:22-slim','sh','-c','read gate && test "$gate" = release && node --max-old-space-size=512 node_modules/typescript/bin/tsc && exec node --max-old-space-size=512 --test --test-concurrency=1 test/secret-form.test.mjs test/ask-secret.test.mjs test/ask-secret-http-registry.test.mjs test/ask-secret-runtime.test.mjs test/sss-run.test.mjs test/public-secret.test.mjs'],text=True).strip()
 row=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
 subprocess.run(['sudo','-n','systemctl','set-property','--runtime','docker-'+cid+'.scope','MemoryHigh=805306368','MemoryMax=1073741824','MemorySwapMax=0','TasksMax=128','CPUQuota=200%'],check=True)
 cg=Path('/sys/fs/cgroup')/Path('/proc/'+str(row['State']['Pid'])+'/cgroup').read_text().strip().split('::')[1].lstrip('/')
 assert(cg/'memory.max').read_text().strip()=='1073741824'
 assert(cg/'memory.swap.max').read_text().strip()=='0'
 assert(cg/'pids.max').read_text().strip()=='128'
 subprocess.run(['docker','exec',cid,'sh','-c','printf "release\\n" > /proc/1/fd/0'],check=True)
 peak=0
 while True:
  state=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]['State']
  if not state['Running']:break
  if time.monotonic()-start>100:raise TimeoutError('emergency test wall limit')
  try:peak=max(peak,int((cg/'memory.peak').read_text()))
  except FileNotFoundError:pass
  time.sleep(.3)
 log=subprocess.run(['docker','logs',cid],capture_output=True,text=True)
 (area/'focused.log').write_text(log.stdout+log.stderr)
 receipt={'exitCode':state['ExitCode'],'elapsedSeconds':round(time.monotonic()-start,3),'peakBytes':peak,'expectedSeconds':10,'maximumSeconds':100,'category':'focused integration','availableBeforeBytes':available,'syntheticOnly':True}
 print(json.dumps(receipt));print((log.stdout+log.stderr)[-7000:]);(area/'receipt.json').write_text(json.dumps(receipt))
 if state['ExitCode']:raise SystemExit(state['ExitCode'])
finally:
 if cid:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,check=True)

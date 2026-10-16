import assert from 'node:assert/strict';
import test from 'node:test';
import {spawn} from 'node:child_process';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';

// Focused integration expected3/max30s. Isolated store, no user secrets:
// real MCP/forms, durable pending over restart, and stateless recovery.
test('first unnamed ask opens a form; retries and restart preserve the same handoff', async t => {
  const home=mkdtempSync(join(tmpdir(),'sss-form-'));
  const listener=createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));
  const port=listener.address().port;await new Promise(r=>listener.close(r));
  const origin=`http://127.0.0.1:${port}`,key='isolated-test-only';let child;
  async function start(){
    child=spawn(process.execPath,['dist/server.js'],{env:{...process.env,HOME:home,SSS_PORT:String(port),SSS_API_KEY:key,SSS_SERVER_URL:origin},stdio:'ignore'});
    for(let i=0;i<100;i++){
      try{if((await fetch(origin)).ok)return;}catch{}
      if(child.exitCode!==null)throw new Error('fixture exited');
      await new Promise(r=>setTimeout(r,30));
    }
    throw new Error('fixture not ready');
  }
  async function stop(){if(child.exitCode===null)await new Promise(r=>{child.once('exit',r);child.kill('SIGTERM');});}
  t.after(stop);await start();
  const client=new Client({name:'secret-form-consumer',version:'1'});
  await client.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:`Bearer ${key}`}}}));
  t.after(()=>client.close());
  const listed=await client.listTools();
  for(const name of ['ask_secret','get_secret'])assert.ok(!(listed.tools.find(x=>x.name===name).inputSchema.required||[]).includes('name'));
  const requestId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const call=async(name,args)=>{
    const result=await client.callTool({name,arguments:args});assert.ok(!result.isError);return result.content[0].text;
  };
  const first=JSON.parse(await call('ask_secret',{request_id:requestId}));
  assert.equal(first.status,'pending');assert.equal(first.name,'secret_'+requestId);
  assert.equal(first.request_id,requestId);
  assert.match(first.input_url,new RegExp(`^${origin}/i/[A-Za-z0-9_-]+$`));assert.ok(!JSON.stringify(first).includes('/d/'));
  const page=await fetch(first.input_url);assert.equal(page.status,200);assert.match(await page.text(),/type=password/);
  assert.equal(JSON.parse(await call('ask_secret',{name:first.name})).input_url,first.input_url);
  const anonymous=JSON.parse(await call('ask_secret',{}));assert.notEqual(anonymous.name,first.name);
  assert.match(await call('get_secret',{}),/\/i\//);
  await stop();await start();
  assert.equal(JSON.parse(await call('ask_secret',{request_id:requestId})).input_url,first.input_url);
  const stale=await fetch(origin+'/mcp',{method:'POST',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json',Accept:'application/json, text/event-stream','Mcp-Session-Id':'old-disconnected-session'},body:JSON.stringify({jsonrpc:'2.0',id:88,method:'tools/call',params:{name:'ask_secret',arguments:{name:first.name}}})});
  assert.equal(stale.status,200);assert.equal(stale.headers.get('mcp-session-id'),null);
  const value='synthetic-form-canary-value';
  const submitted=await fetch(first.input_url.replace('/i/','/submit/'),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({value})});
  assert.ok(submitted.ok);assert.ok(!(await submitted.text()).includes(value));
  const ready=await call('ask_secret',{name:first.name});assert.deepEqual(JSON.parse(ready),{status:'ready',name:first.name});
  assert.ok(!ready.includes(value));assert.equal((await fetch(first.input_url)).status,410);
});

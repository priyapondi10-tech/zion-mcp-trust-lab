const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const sensitive = /token|secret|password|api.?key|authorization|credential|private.?key/i;
const reference = value => { const s=String(value).trim(); return /^(env:|process\.env\.|your[_ -]|<[^>]+>$|\[REDACTED\]$)/i.test(s) || (s.includes('${') && s.replace(/\$\{[^}]+\}/g,'').replace(/^Bearer\s*/i,'').trim()===''); };
export function audit(input) {
  if (!object(input)) throw new Error('Provide a JSON object, not an array or scalar.');
  const config=input.mcpServers ?? input.servers ?? {};
  const manifest=input.tools ?? input.result?.tools ?? [];
  if (!object(config) || !Array.isArray(manifest)) throw new Error('Servers must be an object and tools must be an array.');
  const entries=Object.entries(config);
  if (entries.length>200 || manifest.length>1000) throw new Error('Limit the review to 200 servers and 1,000 tools.');
  if (!entries.length && !manifest.length) throw new Error('Add at least one server or tool under mcpServers, servers or tools.');
  const findings=[], servers=[], tools=[];
  const add=(severity,subject,title,detail,recommendation)=>findings.push({severity,subject:String(subject).slice(0,200),title,detail,recommendation});
  for (const [rawName,s] of entries) {
    const name=rawName.slice(0,200);
    if (!object(s)) { add('high',name,'Invalid server definition','The server entry is not an object.','Validate the client configuration before use.'); continue; }
    servers.push({name,transport:s.url?'remote':'stdio'});
    const command=String(s.command??'').split(/[\\/]/).pop().replace(/\.exe$/i,'').toLowerCase();
    const args=Array.isArray(s.args)?s.args.map(String):[];
    if (['sh','bash','zsh','cmd','powershell','pwsh'].includes(command)) add('high',name,'Shell execution boundary','A shell launcher can interpret commands and metacharacters.','Prefer a direct executable; review all arguments and isolate the process.');
    if (['npx','uvx','pipx','docker'].includes(command)) {
      const immutable=command==='docker'?args.some(a=>a.includes('@sha256:')):args.some(a=>/(?:@|==)\d+\.\d+/.test(a));
      if (!immutable) add('medium',name,'Launcher is not immutably pinned','The package/image launcher has no recognized version or image digest.','Pin a reviewed version; use an image digest where supported and verify provenance.');
      if(args.includes('-y')||args.includes('--yes'))add('medium',name,'Automatic package execution','The launcher bypasses its installation prompt.','Preinstall reviewed packages instead of implicitly trusting fresh downloads.');
    }
    if(args.some(a=>a==='/'||a==='~'||/^[A-Za-z]:[\\/]?$/.test(a)))add('high',name,'Broad filesystem argument','An argument appears to grant a filesystem or home-directory root.','Limit accessible paths to a dedicated workspace.');
    const permissions=JSON.stringify(s.permissions??s.scopes??[]);
    if(s.allowAll===true||s.dangerouslyAllowAll===true||/"\*"|"all"/.test(permissions))add('high',name,'Broad capability scope','The configuration declares an allow-all or wildcard scope.','Replace wildcard access with an explicit allowlist and approval gates.');
    for(const field of ['env','headers']) {
      if(s[field]!==undefined&&!object(s[field])) {add('medium',name,'Unexpected '+field+' format','The field is not a key/value object.','Use the format expected by your MCP client.');continue;}
      for(const [key,value] of Object.entries(s[field]??{})) {
        if(sensitive.test(key)&&value!==null&&String(value).trim()!==''&&!reference(value))add('high',name,'Possible literal credential in '+field,'A credential-like field contains a literal value; its name and value are omitted from this report.','Use the client secret store or environment references; rotate any real exposed credential.');
      }
    }
    if(args.some(a=>/--(?:token|password|api-key|secret)(?:=|$)|\bsk-[A-Za-z0-9_-]{12,}/i.test(a)))add('high',name,'Possible credential argument','A command argument may expose a credential in process listings.','Use a secret store or supported environment reference.');
    if(s.url) {
      try {const u=new URL(String(s.url));const local=['localhost','127.0.0.1','[::1]'].includes(u.hostname);
        if(!['https:','http:'].includes(u.protocol))add('medium',name,'Unsupported endpoint scheme','Only HTTP(S) endpoints are assessed.','Verify the client transport and endpoint manually.');
        if(u.protocol==='http:'&&!local)add('high',name,'Unencrypted remote endpoint','The remote URL uses HTTP outside recognized loopback hosts.','Use HTTPS and validate the server identity.');
        if(u.username||u.password||[...u.searchParams.keys()].some(k=>sensitive.test(k)))add('high',name,'Credential-bearing URL','The URL contains user information or credential-like query keys. Values are omitted.','Move credentials to a secret-backed authentication mechanism.');
      }catch{add('high',name,'Malformed endpoint URL','The URL could not be parsed.','Correct the endpoint before connecting.');}
    }
    if(!s.url&&!s.command)add('medium',name,'Missing connection details','Neither a command nor URL is declared.','Check the client-specific transport settings.');
  }
  for(let i=0;i<manifest.length;i++) {
    const t=manifest[i]; const name=String(t?.name??'tool-'+(i+1)).slice(0,200);
    if(!object(t)){add('medium',name,'Invalid tool definition','Tool metadata is not an object.','Validate the tools-list response.');continue;}
    tools.push({name,readOnlyHint:t.annotations?.readOnlyHint===true,destructiveHint:t.annotations?.destructiveHint===true});
    if(t.annotations?.destructiveHint===true||/delete|destroy|drop_|exec|shell|run_command|write_file|payment|send_email/i.test(name))add('high',name,'Potentially mutating or destructive tool','The name or annotation suggests write, execution, deletion or external-send capability.','Require explicit human approval, least privilege and an isolated test environment.');
    if(!object(t.inputSchema)||t.inputSchema.additionalProperties!==false)add('medium',name,'Open input surface','The input schema does not explicitly reject extra properties.','Validate allowed fields server-side; review additionalProperties and required fields.');
    if(/ignore.{0,35}(previous|instructions)|override.{0,25}system|exfiltrat|send.{0,30}secret/i.test(String(t.description??'')))add('high',name,'Tool-description review trigger','The description matches a basic instruction-override or exfiltration phrase rule.','Treat tool metadata as untrusted text; inspect the complete manifest manually.');
  }
  const weights={critical:35,high:20,medium:8,low:2,info:0};
  findings.sort((a,b)=>weights[b.severity]-weights[a.severity]);
  const counts=Object.fromEntries(Object.keys(weights).map(k=>[k,findings.filter(f=>f.severity===k).length]));
  return {version:'1.0.0',score:Math.max(0,100-findings.reduce((n,f)=>n+weights[f.severity],0)),counts,servers,tools,findings,disclaimer:'Static heuristic triage only. No server or tool was executed. Absence of findings is not evidence of safety. Environment/header values are omitted; names are retained.'};
}
export function markdown(report){const clean=s=>String(s).replace(/[\r\n`<>]/g,' ');return '# MCP Trust Lab — human review\n\n'+report.disclaimer+'\n\nReview score: '+report.score+'/100 (heuristic only)\n\n'+(report.findings.map(f=>'- [ ] **'+f.severity.toUpperCase()+' — '+clean(f.title)+'** ('+clean(f.subject)+')\n  '+f.detail+' '+f.recommendation).join('\n\n')||'No rules fired. Review provenance, sandboxing and permissions manually.')+'\n';}

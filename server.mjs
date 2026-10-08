import http from 'node:http';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';

const root=new URL('./',import.meta.url);
export const DEFAULT_GUESTS=[{"name":"지은","message":"둘이 함께할 모든 날을 응원해 ♡","skin":0,"hair":9,"color":1,"shirt":3,"id":"example-0","example":true,"accessory":0,"outfit":6},{"name":"민수","message":"결혼 축하해! 행복하게 잘 살아 🌷","skin":1,"hair":4,"color":0,"shirt":2,"id":"example-1","example":true,"accessory":0,"outfit":4},{"name":"수진","message":"오늘 세상에서 제일 예쁜 두 사람!","skin":0,"hair":3,"color":0,"shirt":4,"id":"example-2","example":true,"accessory":0,"outfit":7},{"name":"도윤","message":"웃음 가득한 날들만 이어지길!","skin":2,"hair":1,"color":1,"shirt":1,"id":"example-3","example":true,"accessory":0,"outfit":2},{"name":"유나","message":"오래오래 서로의 가장 좋은 친구로 ♡","skin":1,"hair":7,"color":2,"shirt":0,"id":"example-4","example":true,"accessory":0,"outfit":8},{"name":"현우","message":"두 사람의 새로운 시작을 축하해!","skin":0,"hair":8,"color":0,"shirt":0,"id":"example-5","example":true,"accessory":0,"outfit":5}];

export const validGuest=g=>g&&typeof g.name==='string'&&g.name.trim()&&Array.from(g.name.trim()).length<=10&&typeof g.message==='string'&&g.message.trim()&&Array.from(g.message.trim()).length<=50&&[['skin',4],['hair',10],['color',10],['shirt',10],['outfit',10]].every(([k,n])=>Number.isInteger(g[k])&&g[k]>=0&&g[k]<n)&&(g.accessory===undefined||(Number.isInteger(g.accessory)&&g.accessory>=0&&g.accessory<10));
const cleanGuest=g=>({name:g.name.trim(),message:g.message.trim(),skin:g.skin,hair:g.hair,color:g.color,shirt:g.shirt,outfit:g.outfit,accessory:g.accessory??0});
const digest=value=>createHash('sha256').update(value).digest();
const problem=(status,message)=>Object.assign(new Error(message),{status});

export async function createGuestbook({dataUrl=new URL('guestbook-data.json',root),adminPassword=process.env.ADMIN_PASSWORD??'',initialGuests=DEFAULT_GUESTS}={}){
 let guests=[],seeded=false;
 try{const stored=JSON.parse(await readFile(dataUrl,'utf8'));seeded=stored?.version===2;guests=Array.isArray(stored)?stored:stored.guests;if(!Array.isArray(guests))throw Error('Invalid guest data');guests=guests.map(g=>({...g,outfit:g.outfit??0,accessory:g.accessory??0}))}catch(e){if(e.code!=='ENOENT')throw e}
 if(!seeded){guests=[...initialGuests.filter(g=>!guests.some(p=>p.id===g.id)),...guests];const migrationTmp=new URL(dataUrl.href+'.tmp');await writeFile(migrationTmp,JSON.stringify({version:2,guests},null,2));await rename(migrationTmp,dataUrl)}
 const adminEnabled=adminPassword.length>=4,passwordHash=digest(adminPassword),sessions=new Map(),attempts=new Map();
 let queue=Promise.resolve();
 const tmp=new URL(dataUrl.href+'.tmp');
 async function mutate(transform){const job=queue.then(async()=>{const {next,result}=transform(guests);await writeFile(tmp,JSON.stringify({version:2,guests:next},null,2));await rename(tmp,dataUrl);guests=next;return result});queue=job.catch(()=>{});return job}
 async function body(req){let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>4096)throw problem(413,'요청 내용이 너무 큽니다.');chunks.push(Buffer.from(chunk))}try{return JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch{throw problem(400,'잘못된 요청입니다.')}}
 function authorized(req){const bearer=req.headers.authorization||'',token=bearer.startsWith('Bearer ')?bearer.slice(7):'',expires=sessions.get(token);if(!expires||expires<=Date.now()){sessions.delete(token);throw problem(401,'관리자 로그인이 필요하거나 만료되었습니다.')}return token}
 const handler=async(req,res)=>{
  const send=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data))};
  try{
   const path=req.url.split('?')[0];
   if(!['GET','HEAD'].includes(req.method)&&req.headers.origin&&![`http://${req.headers.host}`,`https://${req.headers.host}`].includes(req.headers.origin))throw problem(403,'다른 사이트에서는 변경할 수 없습니다.');
   if(path==='/api/admin/login'&&req.method==='POST'){
    if(!adminEnabled)throw problem(503,'서버의 ADMIN_PASSWORD를 4자 이상으로 설정해 주세요.');
    const ip=req.socket.remoteAddress||'unknown',now=Date.now();
    for(const [key,entry]of attempts)if(entry.until<now)attempts.delete(key);
    const entry=attempts.get(ip)||{count:0,until:now+15*60*1000};
    if(entry.count>=10)throw problem(429,'로그인 시도가 많습니다. 15분 뒤 다시 시도해 주세요.');
    entry.count++;attempts.set(ip,entry);const input=await body(req);
    if(typeof input?.password!=='string'||!timingSafeEqual(passwordHash,digest(input.password)))throw problem(401,'관리자 비밀번호가 올바르지 않습니다.');
    attempts.delete(ip);for(const [key,until]of sessions)if(until<=now)sessions.delete(key);
    const token=randomBytes(32).toString('hex');sessions.set(token,now+8*60*60*1000);return send(200,{token});
   }
   if(path==='/api/admin/logout'&&req.method==='POST'){sessions.delete(authorized(req));return send(200,{ok:true})}
   if(path==='/api/guests'&&req.method==='GET')return send(200,guests);
   if(path==='/api/guests'&&req.method==='POST'){
    let input=await body(req);if(input&&input.outfit===undefined)input.outfit=0;
    if(!validGuest(input))throw problem(400,'이름 10자, 메시지 50자와 아바타 선택을 확인해 주세요.');
    const guest={...cleanGuest(input),id:randomUUID(),createdAt:new Date().toISOString()};
    await mutate(current=>({next:[...current,guest],result:guest}));return send(201,guest);
   }
   const match=path.match(/^\/api\/guests\/([^/]+)$/);
   if(match&&['PATCH','DELETE'].includes(req.method)){
    authorized(req);const id=decodeURIComponent(match[1]);let input;
    if(req.method==='PATCH'){input=await body(req);if(!validGuest(input))throw problem(400,'이름 10자, 메시지 50자와 아바타 선택을 확인해 주세요.')}
    const result=await mutate(current=>{const existing=current.find(g=>g.id===id);if(!existing)throw problem(404,'해당 미니미를 찾을 수 없습니다.');
     if(req.method==='DELETE')return {next:current.filter(g=>g.id!==id),result:{ok:true,id}};
     const updated={...existing,...cleanGuest(input),updatedAt:new Date().toISOString()};return {next:current.map(g=>g.id===id?updated:g),result:updated};
    });return send(200,result);
   }
   if((path==='/'||path==='/index.html')&&req.method==='GET'){
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'});return res.end(await readFile(new URL('index.html',root)));
   }
   send(404,{error:'찾을 수 없습니다.'});
  }catch(e){if(!e.status)console.error('Guestbook error:',e.code||e.name);send(e.status||500,{error:e.status?e.message:'저장하지 못했습니다. 다시 시도해 주세요.'})}
 };
 return {handler,adminEnabled};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const app=await createGuestbook();const port=Number(process.env.PORT||3000);
 http.createServer(app.handler).listen(port,process.env.HOST||'127.0.0.1',()=>{
  console.log(`방명록: http://localhost:${port}\n저장 위치: ${fileURLToPath(new URL('guestbook-data.json',root))}`);
  console.log(app.adminEnabled?'관리자 로그인 사용 가능':'관리자 기능 비활성화: ADMIN_PASSWORD를 4자 이상으로 설정해 주세요.');
 });
}

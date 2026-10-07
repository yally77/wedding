// Build copies this source into netlify/functions/guestbook.mjs.
import {getStore} from '@netlify/blobs';
import {createHash,randomBytes,randomUUID,timingSafeEqual} from 'node:crypto';
import {DEFAULT_GUESTS,validGuest} from '../../server.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const fail=(status,message)=>Object.assign(new Error(message),{status});
const clean=g=>Object.fromEntries(['name','message','skin','hair','color','shirt','outfit','accessory'].map(k=>[k,k==='name'||k==='message'?g[k].trim():g[k]??0]));
export async function update(store,key,initial,fn){
 for(let n=0;n<15;n++){
  const old=await store.getWithMetadata(key,{type:'json'});
  const next=fn(old?old.data:structuredClone(initial));
  const result=await store.setJSON(key,next,old?{onlyIfMatch:old.etag}:{onlyIfNew:true});
  if(result.modified)return next;
 }
 throw fail(503,'잠시 뒤 다시 시도해 주세요.');
}
export function createHandler(store,password){return async(request,context={})=>{
 const origin=request.headers.get('origin');
 const allowedOrigin=origin===new URL(request.url).origin||origin==='https://yally77.github.io';
 const cors=origin&&allowedOrigin?{'Access-Control-Allow-Origin':origin,'Vary':'Origin','Access-Control-Allow-Methods':'GET, POST, PATCH, DELETE, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization'}:{};
 if(request.method==='OPTIONS')return new Response(null,{status:allowedOrigin?204:403,headers:cors});
 const send=(status,data)=>new Response(JSON.stringify(data),{status,headers:{...cors,'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
 try{
  const url=new URL(request.url),path=url.pathname.replace(/^\/\.netlify\/functions\/guestbook/,'/api'),method=request.method;
  if(method!=='GET'&&origin&&!allowedOrigin)throw fail(403,'다른 사이트에서는 변경할 수 없습니다.');
  const body=async()=>{const raw=await request.text();if(Buffer.byteLength(raw)>4096)throw fail(413,'요청 내용이 너무 큽니다.');try{return JSON.parse(raw)}catch{throw fail(400,'잘못된 요청입니다.')}};
  const auth=async()=>{const token=(request.headers.get('authorization')||'').replace(/^Bearer /,'');if(!/^[a-f0-9]{64}$/.test(token))throw fail(401,'관리자 로그인이 필요합니다.');const key='session/'+hash(token),session=await store.get(key,{type:'json'});if(!session||session.until<Date.now()||session.password!==hash(password))throw fail(401,'관리자 로그인이 만료되었습니다.');return key};
  if(path==='/api/admin/login'&&method==='POST'){
   if(password.length<4)throw fail(503,'관리자 비밀번호 설정이 필요합니다.');
   const rateKey='attempt/'+hash(context.ip||'unknown');const now=Date.now();
   await update(store,rateKey,{count:0,until:now+900000},entry=>{if(entry.until<now)entry={count:0,until:now+900000};if(entry.count>=10)throw fail(429,'15분 뒤 다시 시도해 주세요.');return {...entry,count:entry.count+1}});
   const input=await body();if(typeof input?.password!=='string'||!timingSafeEqual(Buffer.from(hash(password)),Buffer.from(hash(input.password))))throw fail(401,'관리자 비밀번호가 올바르지 않습니다.');
   const token=randomBytes(32).toString('hex');await store.setJSON('session/'+hash(token),{until:now+28800000,password:hash(password)});return send(200,{token});
  }
  if(path==='/api/admin/logout'&&method==='POST'){await store.delete(await auth());return send(200,{ok:true})}
  if(path==='/api/guests'&&method==='GET'){
   let guests=await store.get('guests',{type:'json'});
   if(guests===null)guests=await update(store,'guests',DEFAULT_GUESTS,g=>g);
   return send(200,guests);
  }
  if(path==='/api/guests'&&method==='POST'){
   const input=await body();if(!validGuest(input))throw fail(400,'이름 10자, 메시지 30자와 아바타 선택을 확인해 주세요.');
   const guest={...clean(input),id:randomUUID(),createdAt:new Date().toISOString()};
   await update(store,'guests',DEFAULT_GUESTS,guests=>[...guests,guest]);return send(201,guest);
  }
  const match=path.match(/^\/api\/guests\/([^/]+)$/);
  if(match&&['PATCH','DELETE'].includes(method)){
   await auth();const id=decodeURIComponent(match[1]);let input,result;
   if(method==='PATCH'){input=await body();if(!validGuest(input))throw fail(400,'이름 10자, 메시지 30자와 아바타 선택을 확인해 주세요.')}
   await update(store,'guests',DEFAULT_GUESTS,guests=>{const existing=guests.find(g=>g.id===id);if(!existing)throw fail(404,'해당 미니미를 찾을 수 없습니다.');if(method==='DELETE'){result={ok:true,id};return guests.filter(g=>g.id!==id)}result={...existing,...clean(input),updatedAt:new Date().toISOString()};return guests.map(g=>g.id===id?result:g)});
   return send(200,result);
  }
  return send(404,{error:'찾을 수 없습니다.'});
 }catch(e){return send(e.status||500,{error:e.status?e.message:'저장하지 못했습니다. 다시 시도해 주세요.'})}
}}
export default (request,context)=>createHandler(getStore({name:'wedding-guestbook',consistency:'strong'}),process.env.ADMIN_PASSWORD||'')(request,context);

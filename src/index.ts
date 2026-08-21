import { AwsClient } from 'aws4fetch';
import { importX509 } from 'jose';

interface Env {
  MEDIA_BUCKET: R2Bucket;
  FIREBASE_PROJECT_ID: string;
  APP_ORIGIN: string;
  R2_ACCOUNT_ID: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  MAX_UPLOAD_BYTES?: string;
  RATE_LIMIT_KV?: KVNamespace;
}

const MAX_DEFAULT = 25 * 1024 * 1024;
const ALLOWED_TYPES = new Set(['video/mp4', 'video/webm', 'video/quicktime', 'video/ogg']);
const memoryRates = new Map<string, { count: number; resetAt: number }>();

function cors(env: Env) {
  const origin = env.APP_ORIGIN || '';
  return {
    'Access-Control-Allow-Origin': origin || 'null',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
function json(data: unknown, status = 200, env?: Env) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type':'application/json; charset=utf-8', ...(env ? cors(env) : {}) }});
}
function unauthorized(env: Env, message='Authentication required') { return json({error:message},401,env); }

async function firebasePublicKey(headerKid: string): Promise<CryptoKey> {
  const response = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com', { cf:{cacheTtl:3600,cacheEverything:true} });
  if (!response.ok) throw new Error('Unable to fetch Firebase signing certificates.');
  const certs = await response.json() as Record<string,string>;
  const cert=certs[headerKid]; if(!cert) throw new Error('Firebase signing key not found.');
  return importX509(cert,'RS256');
}
function base64UrlDecode(value:string):Uint8Array {
  const padded=value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-(value.length%4))%4);
  return Uint8Array.from(atob(padded),c=>c.charCodeAt(0));
}
async function verifyFirebaseToken(token:string,env:Env):Promise<string> {
  const parts=token.split('.'); if(parts.length!==3) throw new Error('Malformed Firebase token.');
  const header=JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))) as {alg?:string;kid?:string};
  const payload=JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1]))) as {iss?:string;aud?:string;sub?:string;exp?:number;iat?:number};
  if(header.alg!=='RS256'||!header.kid) throw new Error('Unsupported Firebase token.');
  if(payload.aud!==env.FIREBASE_PROJECT_ID||payload.iss!==`https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`) throw new Error('Firebase token audience/issuer mismatch.');
  const now=Math.floor(Date.now()/1000);
  if(!payload.sub||payload.sub.length>128||!payload.exp||payload.exp<now||!payload.iat||payload.iat>now+300) throw new Error('Expired or invalid Firebase token.');
  const key=await firebasePublicKey(header.kid);
  const valid=await crypto.subtle.verify({name:'RSASSA-PKCS1-v1_5'},key,base64UrlDecode(parts[2]),new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if(!valid) throw new Error('Invalid Firebase token signature.');
  return payload.sub;
}
function safeExtension(value:string,contentType:string) {
  const allowed=new Set(['mp4','webm','mov','ogg']); const ext=value.toLowerCase().replace(/[^a-z0-9]/g,'');
  if(allowed.has(ext)) return ext;
  return contentType==='video/mp4'?'mp4':contentType==='video/quicktime'?'mov':'webm';
}
function keyFor(uid:string,ext:string){return `videos/${uid}/${crypto.randomUUID()}.${ext}`;}
function mediaUrl(request:Request,key:string){return new URL(`/media/${key.split('/').map(encodeURIComponent).join('/')}`,request.url).toString();}

async function rateLimit(env:Env,uid:string,action:string,limit:number,windowSeconds:number) {
  const now=Date.now();
  const key=`${action}:${uid}`;
  const local=memoryRates.get(key);
  if(!local || local.resetAt<=now) memoryRates.set(key,{count:1,resetAt:now+windowSeconds*1000});
  else if(local.count>=limit) return false;
  else local.count++;
  if(memoryRates.size>5000) {
    for(const [k,v] of memoryRates) if(v.resetAt<=now) memoryRates.delete(k);
  }
  if(env.RATE_LIMIT_KV) {
    const bucket=Math.floor(now/1000/windowSeconds);
    const kvKey=`rl:${action}:${uid}:${bucket}`;
    const current=Number(await env.RATE_LIMIT_KV.get(kvKey) || '0');
    if(current>=limit) return false;
    await env.RATE_LIMIT_KV.put(kvKey,String(current+1),{expirationTtl:windowSeconds+5});
  }
  return true;
}

export default {
  async fetch(request:Request,env:Env):Promise<Response> {
    if(request.method==='OPTIONS') return new Response(null,{status:204,headers:cors(env)});
    const url=new URL(request.url);
    try {
      if(url.pathname==='/health') return json({ok:true,service:'flipcast-media',version:'2.0.0'},200,env);

      const auth=request.headers.get('Authorization')||'';
      if(url.pathname==='/upload-url'&&request.method==='POST') {
        if(!auth.startsWith('Bearer ')) return unauthorized(env);
        const uid=await verifyFirebaseToken(auth.slice(7),env);
        if(!(await rateLimit(env,uid,'upload',10,3600))) return json({error:'Upload rate limit exceeded. Try again later.'},429,env);
        const body=await request.json() as {contentType?:string;size?:number;extension?:string};
        const max=Number(env.MAX_UPLOAD_BYTES||MAX_DEFAULT);
        if(!body.contentType||!ALLOWED_TYPES.has(body.contentType)) return json({error:'Unsupported video type.'},400,env);
        if(!body.size||body.size<=0||body.size>max) return json({error:`Video exceeds the ${Math.round(max/1024/1024)} MB limit.`},413,env);
        const key=keyFor(uid,safeExtension(body.extension||'',body.contentType));
        const endpoint=`https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
        const client=new AwsClient({accessKeyId:env.R2_ACCESS_KEY_ID,secretAccessKey:env.R2_SECRET_ACCESS_KEY,service:'s3',region:'auto'});
        const signed=await client.sign(new Request(`${endpoint}/${encodeURIComponent('flipcast-videos')}/${key}?X-Amz-Expires=900`,{method:'PUT',headers:{'Content-Type':body.contentType}}),{aws:{signQuery:true}});
        return json({key,uploadUrl:signed.url.toString(),mediaUrl:mediaUrl(request,key)},200,env);
      }

      if(url.pathname.startsWith('/media/') && request.method==='DELETE') {
        if(!auth.startsWith('Bearer ')) return unauthorized(env);
        const uid=await verifyFirebaseToken(auth.slice(7),env);
        const key=decodeURIComponent(url.pathname.slice('/media/'.length));
        if(!key.startsWith(`videos/${uid}/`)||key.includes('..')) return new Response('Not found',{status:404,headers:cors(env)});
        if(!(await rateLimit(env,uid,'delete',30,3600))) return json({error:'Delete rate limit exceeded.'},429,env);
        await env.MEDIA_BUCKET.delete(key);
        return new Response(null,{status:204,headers:cors(env)});
      }

      if(url.pathname.startsWith('/media/')&&request.method==='GET') {
        const key=decodeURIComponent(url.pathname.slice('/media/'.length));
        if(!key.startsWith('videos/')||key.includes('..')) return new Response('Not found',{status:404});
        const rangeHeader=request.headers.get('Range'); let range:{offset?:number;length?:number}|undefined;
        if(rangeHeader){const match=/^bytes=(\d+)-(\d*)$/i.exec(rangeHeader.trim());if(!match)return new Response('Invalid range',{status:416});const offset=Number(match[1]);const end=match[2]?Number(match[2]):undefined;range={offset,...(end!==undefined?{length:end-offset+1}:{})};}
        const object=range?await env.MEDIA_BUCKET.get(key,{range}):await env.MEDIA_BUCKET.get(key);
        if(!object)return new Response('Not found',{status:404,headers:cors(env)});
        const headers=new Headers(cors(env)); object.writeHttpMetadata(headers); headers.set('Accept-Ranges','bytes'); headers.set('Cache-Control','public, max-age=31536000, immutable'); headers.set('ETag',object.httpEtag); headers.set('Content-Type',object.httpMetadata?.contentType||'video/mp4');
        if(object.range){headers.set('Content-Range',`bytes ${object.range.offset}-${object.range.offset+object.range.length-1}/${object.size}`);headers.set('Content-Length',String(object.range.length));return new Response(object.body,{status:206,headers});}
        headers.set('Content-Length',String(object.size)); return new Response(object.body,{status:200,headers});
      }
      return json({error:'Not found'},404,env);
    } catch(error) { console.error(error); return json({error:error instanceof Error?error.message:'Internal server error'},500,env); }
  },
  async scheduled(_event:ScheduledEvent,env:Env) {
    const cutoff=Date.now()-25*60*60*1000;
    let cursor:string|undefined;
    do {
      const listed=await env.MEDIA_BUCKET.list({prefix:'videos/',cursor,limit:1000});
      const expired=listed.objects.filter(o=>o.uploaded.getTime()<cutoff).map(o=>o.key);
      if(expired.length) await env.MEDIA_BUCKET.delete(expired);
      cursor=listed.truncated?listed.cursor:undefined;
    } while(cursor);
  }
} satisfies ExportedHandler<Env>;

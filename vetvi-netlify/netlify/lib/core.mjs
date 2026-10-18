import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
const COOKIE='vetvi_session';
const AGE=12*60*60;
const digest=value=>createHash('sha256').update(value).digest();
export class HttpError extends Error { constructor(status,message){super(message);this.status=status;} }
export function settings(env=process.env){
  const password=env.VETVI_PASSWORD,secret=env.VETVI_SESSION_SECRET;
  if(typeof password!=='string'||password.length<12||typeof secret!=='string'||secret.length<32)throw new HttpError(503,'Владелец сайта ещё не настроил пароль. В Netlify нужны VETVI_PASSWORD (от 12 символов) и VETVI_SESSION_SECRET (от 32 символов), затем новый deploy.');
  return {password,secret};
}
export function reply(value,status=200,headers={}){return Response.json(value,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});}
export function failure(error){return reply({error:error instanceof HttpError?error.message:'Не удалось сохранить или загрузить данные. Попробуйте ещё раз.'},error instanceof HttpError?error.status:500);}
export function passwordMatches(candidate,configured){return typeof candidate==='string'&&candidate.length<=1024&&timingSafeEqual(digest(candidate),digest(configured));}
export function checkOrigin(request){
  const origin=request.headers.get('origin');
  if(request.headers.get('sec-fetch-site')==='cross-site'||!origin||origin!==new URL(request.url).origin)throw new HttpError(403,'Недопустимый источник запроса.');
}
export async function readJson(request,limit=3_000_000){
  if(!request.headers.get('content-type')?.includes('application/json'))throw new HttpError(415,'Ожидался JSON.');
  const reader=request.body?.getReader();if(!reader)throw new HttpError(400,'Пустой запрос.');
  const chunks=[];let length=0;
  for(;;){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>limit){await reader.cancel();throw new HttpError(413,'Слишком большой запрос.');}chunks.push(value);}
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new HttpError(400,'Некорректный JSON.');}
}
const sign=(value,secret)=>createHmac('sha256',secret).update(value).digest('base64url');
export function makeSession(config,now=Date.now()){
  const value=Buffer.from(JSON.stringify({exp:now+AGE*1000,nonce:randomBytes(24).toString('hex'),version:sign('password:'+config.password,config.secret)})).toString('base64url');
  return `${value}.${sign(value,config.secret)}`;
}
export function sessionCookie(token,request,clear=false){
  const secure=new URL(request.url).protocol==='https:'?'; Secure':'';
  return `${COOKIE}=${clear?'':token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${clear?0:AGE}${secure}`;
}
export async function authorize(request,store,config,now=Date.now()){
  const token=(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);
  if(!token||token.length>1500)throw new HttpError(401,'Введите пароль, чтобы открыть заметки.');
  const [value,signature,...extra]=token.split('.');
  if(extra.length||!value||!signature||!passwordMatches(signature,sign(value,config.secret)))throw new HttpError(401,'Сеанс завершён. Войдите снова.');
  let payload;try{payload=JSON.parse(Buffer.from(value,'base64url').toString('utf8'));}catch{throw new HttpError(401,'Недопустимый сеанс.');}
  if(!Number.isSafeInteger(payload.exp)||payload.exp<=now||payload.exp>now+AGE*1000||payload.version!==sign('password:'+config.password,config.secret))throw new HttpError(401,'Сеанс завершён. Войдите снова.');
  if(await store.get(`revoked/${digest(token).toString('hex')}`))throw new HttpError(401,'Сеанс завершён. Войдите снова.');
  return token;
}
export async function revoke(token,store){await store.setJSON(`revoked/${digest(token).toString('hex')}`,{revokedAt:Date.now()});}
export async function limitLogin(store,ip,now=Date.now()){
  const key=`attempts/${digest(ip||'unknown').toString('hex')}`;
  for(let retry=0;retry<5;retry++){
    const current=await store.getWithMetadata(key,{type:'json'});
    const state=current?.data?.until>now?current.data:{count:0,until:now+15*60*1000};
    if(state.count>=10)throw new HttpError(429,'Слишком много попыток. Подождите 15 минут.');
    const result=await store.setJSON(key,{count:state.count+1,until:state.until},current?{onlyIfMatch:current.etag}:{onlyIfNew:true});
    if(result.modified)return;
  }
  throw new HttpError(429,'Подождите немного и повторите вход.');
}
export function validateVault(body){
  const {payload:p,revision:r}=body??{};
  if(!Number.isSafeInteger(r)||r<0||!p||p.v!==1||p.iterations!==310000||typeof p.salt!=='string'||!/^[A-Za-z0-9+/]{22}==$/.test(p.salt)||typeof p.iv!=='string'||!/^[A-Za-z0-9+/]{16}$/.test(p.iv)||typeof p.data!=='string'||p.data.length<24||p.data.length>2_700_000||!/^[A-Za-z0-9+/]+={0,2}$/.test(p.data))throw new HttpError(400,'Некорректное хранилище.');
}
export async function vaultHandler(request,store,config){
  await authorize(request,store,config);
  if(request.method==='GET'){
    const row=await store.getWithMetadata('notebook',{type:'json'});
    return reply(row?.data??{payload:null,revision:0});
  }
  if(request.method!=='PUT')throw new HttpError(405,'Метод не поддерживается.');
  checkOrigin(request);const body=await readJson(request);validateVault(body);
  const current=await store.getWithMetadata('notebook',{type:'json'});
  if((current?.data?.revision??0)!==body.revision)throw new HttpError(409,'Дерево изменено в другой вкладке. Скачайте копию текущих заметок и обновите страницу.');
  const value={payload:body.payload,revision:body.revision+1};
  const result=await store.setJSON('notebook',value,current?{onlyIfMatch:current.etag}:{onlyIfNew:true});
  if(!result.modified)throw new HttpError(409,'Другой сеанс уже сохранил изменения. Скачайте копию и обновите страницу.');
  return reply({revision:value.revision});
}
export async function loginHandler(request,store,config,ip){
  if(request.method!=='POST')throw new HttpError(405,'Метод не поддерживается.');
  checkOrigin(request);await limitLogin(store,ip);const body=await readJson(request,4096);
  if(!passwordMatches(body?.password,config.password))throw new HttpError(401,'Неверный пароль.');
  return reply({ok:true},200,{'Set-Cookie':sessionCookie(makeSession(config),request)});
}
export async function logoutHandler(request,store,config){
  if(request.method!=='POST')throw new HttpError(405,'Метод не поддерживается.');
  checkOrigin(request);
  try{await revoke(await authorize(request,store,config),store);}catch(e){if(!(e instanceof HttpError)||e.status!==401)throw e;}
  return reply({ok:true},200,{'Set-Cookie':sessionCookie('',request,true)});
}

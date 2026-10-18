export type Branch = { id:string; parent:string|null; title:string; text:string; x:number; y:number; color:string; status:"note"|"todo"|"doing"|"done"; collapsed?:boolean };
export type Tree = { id:string; name:string; nodes:Branch[] };
export type Notebook = { version:1; trees:Tree[] };
export type Envelope = { v:1; iterations:310000; salt:string; iv:string; data:string };
export const palette = ["sage","sand","blue","rose","lavender"];
export const uid = () => crypto.randomUUID();
export function initialNotebook(): Notebook {
  return {version:1,trees:[{id:uid(),name:"Моё пространство",nodes:[
    {id:"root",parent:null,title:"Моё пространство",text:"Здесь начинается ваше дерево мыслей.\n\nОдна ветка — одна идея, заметка или задача. Выберите карточку, чтобы писать, и добавляйте новые ветки в любую сторону.\n\nПеретащите карточки, чтобы выстроить собственную картину.",x:0,y:150,color:"sage",status:"note"},
    {id:"ideas",parent:"root",title:"Идеи и вдохновение",text:"Место для мыслей, которым пока рано становиться планом.\n\nЧто хочется попробовать? Какой вопрос не даёт покоя?",x:-300,y:-40,color:"sand",status:"note"},
    {id:"plans",parent:"root",title:"Планы на неделю",text:"Выберите одно важное дело. Разбейте его на небольшие шаги — каждый шаг может стать новой веткой.",x:0,y:-90,color:"sage",status:"doing"},
    {id:"notes",parent:"root",title:"Личные заметки",text:"Пишите свободно. Здесь достаточно места для длинных текстов, списков и наблюдений.",x:300,y:-40,color:"blue",status:"note"},
    {id:"step",parent:"plans",title:"Первый маленький шаг",text:"Добавить свою первую ветку и записать одну мысль.",x:0,y:-310,color:"sage",status:"todo"},
    {id:"read",parent:"notes",title:"Что почитать",text:"Книги, статьи и мысли, к которым хочется вернуться.",x:310,y:-265,color:"blue",status:"note"},
  ]}]};
}
function b64(bytes:Uint8Array){let out="";for(let i=0;i<bytes.length;i+=8192)out+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(out);}
function bytes(value:string){return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
export function newSalt(){return b64(crypto.getRandomValues(new Uint8Array(16)));}
export async function deriveKey(password:string,salt:string){
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:bytes(salt),iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
export async function encrypt(book:Notebook,key:CryptoKey,salt:string):Promise<Envelope>{
  const plain=new TextEncoder().encode(JSON.stringify(book));
  if(plain.length>2_000_000)throw new Error("Хранилище превышает 2 МБ. Скачайте копию и сократите заметки.");
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plain);
  return {v:1,iterations:310000,salt,iv:b64(iv),data:b64(new Uint8Array(cipher))};
}
export async function decrypt(envelope:Envelope,key:CryptoKey):Promise<Notebook>{
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes(envelope.iv)},key,bytes(envelope.data));
  const book=JSON.parse(new TextDecoder().decode(plain));
  if(book.version!==1||!Array.isArray(book.trees)||!book.trees.length)throw new Error("Неверный формат данных");
  return book;
}
export function markdown(tree:Tree){
  const lines=[`# ${tree.name}`,""];
  function visit(node:Branch,level:number){lines.push(`${"#".repeat(Math.min(level,6))} ${node.status==="done"?"✓ ":""}${node.title}`,"",node.text,"");for(const child of tree.nodes.filter(n=>n.parent===node.id))visit(child,level+1);}
  for(const root of tree.nodes.filter(n=>!n.parent))visit(root,2);
  return lines.join("\n");
}

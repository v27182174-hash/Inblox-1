/* Inblox — сервер (Cloudflare Pages, режим _worker.js + база D1 с привязкой DB).
   Аккаунты, игры, аватары, каталог, лайки, чат, админка и баны. */
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const err=(m,s=400,x={})=>J({error:m,...x},s);
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const bytes=s=>enc.encode(s).length;
const eq=(a,b)=>{ if(a.length!==b.length) return false; let d=0; for(let i=0;i<a.length;i++) d|=a.charCodeAt(i)^b.charCodeAt(i); return d===0; };
async function pbk(pw,saltHex){
  const key=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);
  const salt=Uint8Array.from(saltHex.match(/../g).map(h=>parseInt(h,16)));
  return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},key,256));
}
const FOREVER=4102444800000, DAY=86400000;
const ID_RE=/^[\w\-]{1,40}$/, ROOM_RE=/^[\w:.\-]{1,64}$/;
const SND={perSound:14000000,total:150000000,count:200,chunk:800000,pubTotal:30000000,pubCount:40};
const IMGRE=/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+\/=]+$/;
/* картинки игры (game.images): только data:image, не больше 12 штук и ~0,75 МБ суммарно */
function cleanImages(g){
  if(g.images==null) return; const o={}; let n=0,t=0;
  if(typeof g.images==='object') for(const [id,v] of Object.entries(g.images)){
    if(n>=12||!ID_RE.test(id)||!v||typeof v.data!=='string'||v.data.length>142000||t+v.data.length>760000||!IMGRE.test(v.data)) continue;
    o[id]={name:cleanText(v.name,24)||'Картинка',data:v.data}; n++; t+=v.data.length;
  }
  g.images=o;
}
const LIM={game:1500000,pubGame:900000,pubSounds:900000,avatar:200000,games:200,pubs:30};

async function throttle(db,key,max,win){
  const now=Date.now(), r=await db.prepare('SELECT n,reset FROM rl WHERE k=?').bind(key).first();
  if(!r||r.reset<now){ await db.prepare('INSERT INTO rl(k,n,reset) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=1,reset=excluded.reset').bind(key,now+win).run(); return true; }
  if(r.n>=max) return false;
  await db.prepare('UPDATE rl SET n=n+1 WHERE k=?').bind(key).run(); return true;
}
async function auth(req,db){
  const h=req.headers.get('Authorization')||''; if(!h.startsWith('Bearer ')) return null;
  return await db.prepare('SELECT u.id,u.name,u.role,u.ban_until,u.ban_reason,s.token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.exp>?').bind(await sha(h.slice(7)),Date.now()).first();
}
const banInfo=u=>u.ban_until>Date.now()?{banned:true,reason:u.ban_reason||'',until:u.ban_until}:null;

async function me(db,u,token){
  const gs=(await db.prepare('SELECT json FROM games WHERE owner=? ORDER BY ts').bind(u.id).all()).results||[];
  const row=await db.prepare('SELECT avatar,look FROM users WHERE id=?').bind(u.id).first();
  if(row&&row.avatar&&!row.look){ const lk=lookOf(parse(row.avatar),u.role); if(lk) await db.prepare('UPDATE users SET look=? WHERE id=?').bind(JSON.stringify(lk),u.id).run(); }
  const body='{"user":'+JSON.stringify({id:u.id,name:u.name,role:u.role})+(token?',"token":"'+token+'"':'')+',"games":['+gs.map(r=>r.json).join(',')+'],"avatar":'+((row&&row.avatar)||'null')+'}';
  return new Response(body,{headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
}
async function newSession(db,userId){
  const token=rnd(32), now=Date.now();
  await db.prepare('DELETE FROM sessions WHERE exp<?').bind(now).run();
  await db.prepare('INSERT INTO sessions(token,user_id,created,exp) VALUES(?,?,?,?)').bind(await sha(token),userId,now,now+60*DAY).run();
  return token;
}
const parse=s=>{ try{ return JSON.parse(s); }catch(e){ return null; } };
/* Короткое «лицо» игрока для кружка-аватара (только безопасные поля) */
function lookOf(a,role){
  if(!a||typeof a!=='object') return null;
  const c=v=>typeof v==='string'&&/^#[0-9a-fA-F]{3,8}$/.test(v)?v:undefined, id=v=>typeof v==='string'&&/^[\w\-]{1,20}$/.test(v)?v:undefined;
  const o={skin:c(a.skin),shirt:c(a.shirt),hat:id(a.hat),hatColor:c(a.hatColor),face:id(a.face),head:id(a.head),build:id(a.build),outfit:id(a.outfit),outfitColor:c(a.outfitColor),hair:id(a.hair),hairColor:c(a.hairColor),emblem:id(a.emblem)};
  if(typeof a.shirtTex==='string'&&/^p:[a-z]{1,12}$/.test(a.shirtTex)) o.shirtTex=a.shirtTex;
  if(role==='admin'){ if(a.vipSuit) o.vipSuit=1; if(a.vipShades) o.vipShades=1; }
  for(const k of Object.keys(o)) if(o[k]===undefined) delete o[k];
  return o;
}
/* Колонки bio и look добавляются сами при первом обращении (ничего вручную в базе делать не нужно) */
let schemaOk=false;
async function ensureSchema(db){
  if(schemaOk) return;
  for(const [col,def] of [['bio',"TEXT NOT NULL DEFAULT ''"],['look','TEXT']]){
    try{ await db.prepare('SELECT '+col+' FROM users LIMIT 1').first(); }
    catch(e){ try{ await db.prepare('ALTER TABLE users ADD COLUMN '+col+' '+def).run(); }catch(e2){ console.error(e2); } }
  }
  try{
    await db.batch([
      db.prepare('CREATE TABLE IF NOT EXISTS snd(owner TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL DEFAULT 0,n INTEGER NOT NULL DEFAULT 0,got INTEGER NOT NULL DEFAULT 0,ts INTEGER NOT NULL,PRIMARY KEY(owner,id))'),
      db.prepare('CREATE TABLE IF NOT EXISTS friend(a TEXT NOT NULL,b TEXT NOT NULL,ts INTEGER NOT NULL,PRIMARY KEY(a,b))'),
      db.prepare('CREATE TABLE IF NOT EXISTS freq(src TEXT NOT NULL,dst TEXT NOT NULL,ts INTEGER NOT NULL,PRIMARY KEY(src,dst))'),
      db.prepare('CREATE INDEX IF NOT EXISTS freq_dst ON freq(dst)'),
      db.prepare('CREATE TABLE IF NOT EXISTS snd_chunk(owner TEXT NOT NULL,id TEXT NOT NULL,i INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(owner,id,i))'),
      db.prepare('CREATE TABLE IF NOT EXISTS pub_snd(pub TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL DEFAULT 0,n INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(pub,id))'),
      db.prepare('CREATE TABLE IF NOT EXISTS pub_snd_chunk(pub TEXT NOT NULL,id TEXT NOT NULL,i INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(pub,id,i))')
    ]);
  }catch(e){ console.error(e); }
  schemaOk=true;
}
const cleanText=(s,n)=>String(s==null?'':s).replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e]/g,' ').replace(/\s+/g,' ').trim().slice(0,n);

function thumbOf(g){
  const parts=(g.parts||[]).filter(p=>p&&p.type!=='coin'&&p.sx<150).slice(0,260).map(p=>({type:p.type,x:p.x,y:p.y,z:p.z,sx:p.sx,sy:p.sy,sz:p.sz,color:p.color,shape:p.shape,ry:p.ry}));
  return {cover:typeof g.cover==='string'&&g.cover.length<150000?g.cover:null,settings:{sky:g.settings&&g.settings.sky},parts};
}

async function api(req,env,url){
  const m=req.method, seg=url.pathname.slice(5).split('/').filter(Boolean).map(decodeURIComponent), p=seg.join('/');
  if(p==='ping') return J({db:!!env.DB,bindings:Object.keys(env)});
  const db=env.DB; if(!db) return err('База данных не подключена (видны привязки: '+Object.keys(env).join(', ')+'). Добавьте D1 с именем DB и сделайте новый деплой',500);
  await ensureSchema(db);
  const ip=req.headers.get('CF-Connecting-IP')||'x';
  let raw=null; const body=async()=>{ if(raw===null){ raw=await req.text(); } if(raw.length>3000000) return null; return parse(raw); };
  if(m!=='GET'&&m!=='DELETE'&&m!=='OPTIONS'){ const cl=+req.headers.get('Content-Length')||0; if(cl>3500000) return err('Слишком большой запрос',413); }

  /* ---- вход и регистрация ---- */
  if(p==='register'&&m==='POST'){
    if(!await throttle(db,'r:'+ip,5,3600000)) return err('Слишком много регистраций, попробуйте позже',429);
    const b=await body(), name=String(b&&b.name||'').trim(), pw=String(b&&b.pw||'');
    if(!/^[\p{L}\p{N}_\- ]{2,16}$/u.test(name)) return err('Имя: 2–16 символов — буквы, цифры, _ - и пробел');
    if(pw.length<4||pw.length>64) return err('Пароль: от 4 до 64 символов');
    const cnt=(await db.prepare('SELECT COUNT(*) n FROM users').first()).n;
    if(cnt>0&&/^(admin|админ|moder|модер|inblox)/i.test(name)) return err('Это имя зарезервировано');
    const lc=name.toLowerCase();
    if(await db.prepare('SELECT 1 x FROM users WHERE name_lc=?').bind(lc).first()) return err('Такой ник уже занят',409);
    const skel=lc.replace(/[ _\-]/g,'');   /* «Ivan_1», «ivan 1» и «ivan1» считаются одним ником */
    if(skel&&await db.prepare("SELECT 1 x FROM users WHERE REPLACE(REPLACE(REPLACE(name_lc,' ',''),'_',''),'-','')=?").bind(skel).first()) return err('Такой ник уже занят или слишком похож на чужой',409);
    const id=rnd(8), salt=rnd(16), hash=await pbk(pw,salt), role=cnt===0?'admin':'user';
    try{ await db.prepare('INSERT INTO users(id,name,name_lc,salt,hash,role,created) VALUES(?,?,?,?,?,?,?)').bind(id,name,lc,salt,hash,role,Date.now()).run(); }
    catch(e){ return err('Такое имя уже занято',409); }
    return me(db,{id,name,role},await newSession(db,id));
  }
  if(p==='login'&&m==='POST'){
    if(!await throttle(db,'l:'+ip,30,600000)) return err('Слишком много попыток, подождите 10 минут',429);
    const b=await body(), name=String(b&&b.name||'').trim().toLowerCase(), pw=String(b&&b.pw||'').slice(0,64);
    const u=await db.prepare('SELECT * FROM users WHERE name_lc=?').bind(name).first();
    if(!u||!eq(await pbk(pw,u.salt),u.hash)) return err('Неверное имя или пароль',401);
    const bi=banInfo(u); if(bi) return err('Аккаунт заблокирован',403,bi);
    return me(db,u,await newSession(db,u.id));
  }

  /* ---- дальше нужен вход ---- */
  const u=await auth(req,db); if(!u) return err('Войдите в аккаунт',401);
  const bi=banInfo(u); if(bi) return err('Аккаунт заблокирован',403,bi);

  /* отношение текущего игрока к другому: self | friend | out (я отправил заявку) | in (мне отправили) | none */
  const relOf=async id=>{
    if(id===u.id) return 'self';
    if(await db.prepare('SELECT 1 x FROM friend WHERE a=? AND b=?').bind(u.id,id).first()) return 'friend';
    if(await db.prepare('SELECT 1 x FROM freq WHERE src=? AND dst=?').bind(u.id,id).first()) return 'out';
    if(await db.prepare('SELECT 1 x FROM freq WHERE src=? AND dst=?').bind(id,u.id).first()) return 'in';
    return 'none';
  };

  if(p==='me'&&m==='GET') return me(db,u,null);
  if(p==='logout'&&m==='POST'){ await db.prepare('DELETE FROM sessions WHERE token=?').bind(u.token).run(); return J({ok:1}); }

  if(seg[0]==='games'&&seg.length===2){
    const id=seg[1]; if(!ID_RE.test(id)) return err('Неверный id игры');
    if(m==='PUT'){
      const b=await body(), g=b&&b.game; if(!g||!Array.isArray(g.parts)||g.id!==id) return err('Неверные данные игры');
      cleanImages(g);
      const js=JSON.stringify(g); if(bytes(js)>LIM.game) return err('Игра слишком большая (максимум 1,5 МБ)',413);
      const has=await db.prepare('SELECT 1 x FROM games WHERE owner=? AND id=?').bind(u.id,id).first();
      if(!has){ const n=(await db.prepare('SELECT COUNT(*) n FROM games WHERE owner=?').bind(u.id).first()).n; if(n>=LIM.games) return err('Слишком много игр (максимум '+LIM.games+')',400); }
      await db.prepare('INSERT INTO games(owner,id,json,ts) VALUES(?,?,?,?) ON CONFLICT(owner,id) DO UPDATE SET json=excluded.json,ts=excluded.ts').bind(u.id,id,js,Date.now()).run();
      return J({ok:1});
    }
    if(m==='DELETE'){ await db.prepare('DELETE FROM games WHERE owner=? AND id=?').bind(u.id,id).run(); return J({ok:1}); }
  }
  if(p==='avatar'&&m==='PUT'){
    const b=await body(), a=b&&b.avatar; if(!a||typeof a!=='object') return err('Неверные данные');
    if(u.role!=='admin'){ delete a.vipSuit; delete a.vipShades; }
    a.name=u.name;   /* ник в аватаре всегда равен нику аккаунта */
    const js=JSON.stringify(a); if(bytes(js)>LIM.avatar) return err('Аватар слишком большой',413);
    await db.prepare('UPDATE users SET avatar=?,look=? WHERE id=?').bind(js,JSON.stringify(lookOf(a,u.role)),u.id).run(); return J({ok:1});
  }

  /* ---- звуки пользователя (хранятся кусками в D1, чтобы обойти лимит строки 2 МБ) ---- */
  if(seg[0]==='sounds'){
    if(seg.length===1&&m==='GET'){
      const rs=(await db.prepare('SELECT id,name,size FROM snd WHERE owner=? AND n>0 AND got=n ORDER BY ts').bind(u.id).all()).results||[];
      return J({items:rs});
    }
    const id=seg[1]; if(!ID_RE.test(id||'')) return err('Неверный id звука');
    if(seg.length===2&&m==='GET'){
      const r=await db.prepare('SELECT name,n,got FROM snd WHERE owner=? AND id=?').bind(u.id,id).first();
      if(!r||r.n<1||r.got!==r.n) return err('Звук не найден',404);
      const cs=(await db.prepare('SELECT data FROM snd_chunk WHERE owner=? AND id=? ORDER BY i').bind(u.id,id).all()).results||[];
      return J({id,name:r.name,data:cs.map(c=>c.data).join('')});
    }
    if(seg.length===2&&m==='DELETE'){
      await db.batch([db.prepare('DELETE FROM snd_chunk WHERE owner=? AND id=?').bind(u.id,id),db.prepare('DELETE FROM snd WHERE owner=? AND id=?').bind(u.id,id)]);
      return J({ok:1});
    }
    if(seg.length===3&&m==='PUT'){
      if(!await throttle(db,'snd:'+u.id,400,600000)) return err('Слишком много загрузок, подождите немного',429);
      const i=parseInt(seg[2]), b=await body(); if(!b) return err('Неверные данные');
      const total=parseInt(b.total), data=b.data;
      if(!(total>=1&&total<=40)||!(i>=0&&i<total)||typeof data!=='string'||!data.length||data.length>SND.chunk) return err('Неверный кусок звука');
      const others=await db.prepare('SELECT COALESCE(SUM(size),0) s,COUNT(*) c FROM snd WHERE owner=? AND id<>?').bind(u.id,id).first();
      if(i===0){
        if(!data.startsWith('data:audio')) return err('Это не звуковой файл');
        if(others.c>=SND.count) return err('Слишком много звуков (максимум '+SND.count+')');
        await db.batch([
          db.prepare('DELETE FROM snd_chunk WHERE owner=? AND id=?').bind(u.id,id),
          db.prepare('INSERT INTO snd(owner,id,name,size,n,got,ts) VALUES(?,?,?,0,?,0,?) ON CONFLICT(owner,id) DO UPDATE SET name=excluded.name,size=0,n=excluded.n,got=0,ts=excluded.ts').bind(u.id,id,cleanText(b.name,40)||'Звук',total,Date.now())
        ]);
      }
      const meta=await db.prepare('SELECT n,got,size FROM snd WHERE owner=? AND id=?').bind(u.id,id).first();
      if(!meta||meta.n!==total||meta.got!==i) return err('Загрузка прервана, начните заново',409);
      const size=meta.size+data.length;
      if(size>SND.perSound||others.s+size>SND.total){
        await db.batch([db.prepare('DELETE FROM snd_chunk WHERE owner=? AND id=?').bind(u.id,id),db.prepare('DELETE FROM snd WHERE owner=? AND id=?').bind(u.id,id)]);
        return err(size>SND.perSound?'Звук слишком большой (максимум 10 МБ)':'Нет места для звуков на сервере (максимум 150 МБ на аккаунт)',413);
      }
      await db.batch([
        db.prepare('INSERT OR REPLACE INTO snd_chunk(owner,id,i,data) VALUES(?,?,?,?)').bind(u.id,id,i,data),
        db.prepare('UPDATE snd SET got=got+1,size=?,ts=? WHERE owner=? AND id=?').bind(size,Date.now(),u.id,id)
      ]);
      return J({ok:1,done:i===total-1});
    }
  }

  /* ---- каталог игр ---- */
  if(seg[0]==='pub'){
    if(seg.length===1&&m==='GET'){
      const rs=(await db.prepare('SELECT p.id,p.name,p.descr,p.owner,x.name author,x.role arole,x.look,p.ts,p.plays,p.thumb,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id AND user_id=?) liked FROM pub p JOIN users x ON x.id=p.owner ORDER BY p.ts DESC LIMIT 40').bind(u.id).all()).results||[];
      return J({items:rs.map(r=>({id:r.id,name:r.name,desc:r.descr,authorId:r.owner,authorName:r.author,authorRole:r.arole,look:parse(r.look),ts:r.ts,plays:r.plays,likes:r.likes,liked:!!r.liked,game:parse(r.thumb)||{parts:[]}}))});
    }
    if(seg.length===1&&m==='POST'){
      const b=await body(), g=b&&b.game; if(!g||!Array.isArray(g.parts)||!ID_RE.test(g.id||'')) return err('Неверные данные игры');
      if(g.script!=null&&(typeof g.script!=='string'||g.script.length>30000)) return err('Скрипт слишком длинный (максимум 30 000 символов)',413);
      /* звуки игры: клиент присылает только id — сервер сам копирует их из загруженных звуков автора (кусками, без лимита в 1 МБ) */
      const sndIn=Array.isArray(b.sounds)?b.sounds.filter(s=>s&&typeof s.id==='string'&&ID_RE.test(s.id)):[];
      const snd=sndIn.filter(s=>typeof s.data==='string'&&s.data.startsWith('data:audio')).map(s=>({id:s.id.slice(0,40),name:cleanText(s.name,40),data:s.data}));
      const sids=[...new Set(sndIn.filter(s=>typeof s.data!=='string').map(s=>s.id))].slice(0,SND.pubCount);
      let own=[];
      if(sids.length){
        own=(await db.prepare('SELECT id,name,size,n FROM snd WHERE owner=? AND n>0 AND got=n AND id IN ('+sids.map(()=>'?').join(',')+')').bind(u.id,...sids).all()).results||[];
        if(own.reduce((a,r)=>a+r.size,0)>SND.pubTotal) return err('Звуки игры слишком большие для публикации (максимум 30 МБ)',413);
      }
      cleanImages(g);
      const gj=JSON.stringify(g), sj=JSON.stringify(snd);
      if(bytes(gj)>LIM.pubGame) return err('Игра слишком большая для публикации (максимум 0,9 МБ)',413);
      if(bytes(sj)>LIM.pubSounds) return err('Слишком большие звуки в старом формате, обновите страницу и опубликуйте снова',413);
      const name=cleanText(g.name,40)||'Игра', desc=b.desc==null?null:cleanText(b.desc,500).slice(0,500), th=JSON.stringify(thumbOf(g));
      const ex=await db.prepare('SELECT owner FROM pub WHERE id=?').bind(g.id).first();
      if(ex){
        if(ex.owner!==u.id) return err('Эта игра принадлежит другому автору',403);
        await db.prepare('UPDATE pub SET name=?,json=?,sounds=?,thumb=?,descr=COALESCE(?,descr) WHERE id=?').bind(name,gj,sj,th,desc,g.id).run();
      }else{
        const n=(await db.prepare('SELECT COUNT(*) n FROM pub WHERE owner=?').bind(u.id).first()).n; if(n>=LIM.pubs) return err('Можно опубликовать не больше '+LIM.pubs+' игр',400);
        await db.prepare('INSERT INTO pub(id,owner,name,descr,json,sounds,thumb,ts,plays) VALUES(?,?,?,?,?,?,?,?,0)').bind(g.id,u.id,name,desc||'',gj,sj,th,Date.now()).run();
      }
      const st=[db.prepare('DELETE FROM pub_snd_chunk WHERE pub=?').bind(g.id),db.prepare('DELETE FROM pub_snd WHERE pub=?').bind(g.id)];
      for(const r of own){
        st.push(db.prepare('INSERT INTO pub_snd(pub,id,name,size,n) VALUES(?,?,?,?,?)').bind(g.id,r.id,r.name,r.size,r.n));
        st.push(db.prepare('INSERT INTO pub_snd_chunk(pub,id,i,data) SELECT ?,id,i,data FROM snd_chunk WHERE owner=? AND id=?').bind(g.id,u.id,r.id));
      }
      await db.batch(st);
      return J({ok:1});
    }
    const id=seg[1]; if(!id||!ID_RE.test(id)) return err('Неверный id',400);
    if(seg.length===2&&m==='GET'){
      const r=await db.prepare('SELECT p.*,x.name author,x.role arole,x.look,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id AND user_id=?) liked FROM pub p JOIN users x ON x.id=p.owner WHERE p.id=?').bind(u.id,id).first();
      if(!r) return err('Игра не найдена',404);
      const ps=(await db.prepare('SELECT id,name,size FROM pub_snd WHERE pub=? ORDER BY id').bind(id).all()).results||[];
      return J({item:{id:r.id,name:r.name,desc:r.descr,authorId:r.owner,authorName:r.author,authorRole:r.arole,look:parse(r.look),ts:r.ts,plays:r.plays,likes:r.likes,liked:!!r.liked,game:parse(r.json),sounds:(parse(r.sounds)||[]).concat(ps.map(x=>({id:x.id,name:x.name,size:x.size})))}});
    }
    if(seg.length===2&&m==='PATCH'){
      const b=await body()||{}; let ch=0;
      if(b.desc!==undefined){ const r=await db.prepare('UPDATE pub SET descr=? WHERE id=? AND owner=?').bind(cleanText(b.desc,500),id,u.id).run(); ch+=(r.meta&&r.meta.changes)||0; }
      if(b.name!==undefined){ const nm=cleanText(b.name,40); if(!nm) return err('Пустое название');
        const r=await db.prepare("UPDATE pub SET name=?,json=json_set(json,'$.name',?) WHERE id=? AND owner=?").bind(nm,nm,id,u.id).run(); ch+=(r.meta&&r.meta.changes)||0; }
      return ch?J({ok:1}):err('Нет доступа',403);
    }
    if(seg.length===2&&m==='DELETE'){
      const r=u.role==='admin'?await db.prepare('DELETE FROM pub WHERE id=?').bind(id).run():await db.prepare('DELETE FROM pub WHERE id=? AND owner=?').bind(id,u.id).run();
      if(!(r.meta&&r.meta.changes)) return err('Нет доступа',403);
      await db.batch([db.prepare('DELETE FROM likes WHERE pub_id=?').bind(id),db.prepare('DELETE FROM pub_snd_chunk WHERE pub=?').bind(id),db.prepare('DELETE FROM pub_snd WHERE pub=?').bind(id)]); return J({ok:1});
    }
    if(seg.length===4&&seg[2]==='sound'&&m==='GET'){
      const sid=seg[3]; if(!ID_RE.test(sid)) return err('Неверный id звука');
      const r=await db.prepare('SELECT name,n FROM pub_snd WHERE pub=? AND id=?').bind(id,sid).first(); if(!r) return err('Звук не найден',404);
      const cs=(await db.prepare('SELECT data FROM pub_snd_chunk WHERE pub=? AND id=? ORDER BY i').bind(id,sid).all()).results||[];
      if(cs.length!==r.n) return err('Звук повреждён',404);
      return J({id:sid,name:r.name,data:cs.map(c=>c.data).join('')});
    }
    if(seg.length===3&&seg[2]==='like'&&m==='POST'){
      if(!await db.prepare('SELECT 1 x FROM pub WHERE id=?').bind(id).first()) return err('Игра не найдена',404);
      const d=await db.prepare('DELETE FROM likes WHERE pub_id=? AND user_id=?').bind(id,u.id).run(); let liked=false;
      if(!(d.meta&&d.meta.changes)){ await db.prepare('INSERT OR IGNORE INTO likes(pub_id,user_id) VALUES(?,?)').bind(id,u.id).run(); liked=true; }
      const c=(await db.prepare('SELECT COUNT(*) n FROM likes WHERE pub_id=?').bind(id).first()).n; return J({liked,count:c});
    }
    if(seg.length===3&&seg[2]==='play'&&m==='POST'){ await db.prepare('UPDATE pub SET plays=plays+1 WHERE id=?').bind(id).run(); return J({ok:1}); }
  }

  /* ---- профили ---- */
  if(seg[0]==='profile'){
    if(seg.length===2&&m==='GET'){
      const id=seg[1]; if(!ID_RE.test(id)) return err('Неверный id');
      const r=await db.prepare('SELECT id,name,role,created,bio,look FROM users WHERE id=?').bind(id).first(); if(!r) return err('Игрок не найден',404);
      const gs=(await db.prepare('SELECT p.id,p.name,p.descr,p.ts,p.plays,p.thumb,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id AND user_id=?) liked FROM pub p WHERE p.owner=? ORDER BY p.ts DESC LIMIT 40').bind(u.id,id).all()).results||[];
      const look=parse(r.look), games=gs.map(g=>({id:g.id,name:g.name,desc:g.descr,authorId:r.id,authorName:r.name,authorRole:r.role,look,ts:g.ts,plays:g.plays,likes:g.likes,liked:!!g.liked,game:parse(g.thumb)||{parts:[]}}));
      return J({profile:{id:r.id,name:r.name,role:r.role,created:r.created,bio:r.bio||'',rel:await relOf(r.id),look,games,stats:{games:games.length,likes:games.reduce((a,g)=>a+g.likes,0),plays:games.reduce((a,g)=>a+(g.plays||0),0)}}});
    }
    if(seg.length===1&&m==='PATCH'){
      const b=await body(); if(!b) return err('Неверные данные');
      const bio=String(b.bio==null?'':b.bio).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e]/g,'').replace(/\r/g,'').trim().slice(0,300);
      await db.prepare('UPDATE users SET bio=? WHERE id=?').bind(bio,u.id).run(); return J({ok:1,bio});
    }
  }

  /* ---- друзья ---- */
  if(seg[0]==='friends'){
    const fmt=r=>({id:r.id,name:r.name,role:r.role,look:parse(r.look)});
    if(seg.length===1&&m==='GET'){
      const fr=(await db.prepare('SELECT u.id,u.name,u.role,u.look FROM friend f JOIN users u ON u.id=f.b WHERE f.a=? ORDER BY u.name_lc LIMIT 200').bind(u.id).all()).results||[];
      const inc=(await db.prepare('SELECT u.id,u.name,u.role,u.look FROM freq q JOIN users u ON u.id=q.src WHERE q.dst=? ORDER BY q.ts DESC LIMIT 100').bind(u.id).all()).results||[];
      const out=(await db.prepare('SELECT u.id,u.name,u.role,u.look FROM freq q JOIN users u ON u.id=q.dst WHERE q.src=? ORDER BY q.ts DESC LIMIT 100').bind(u.id).all()).results||[];
      return J({friends:fr.map(fmt),incoming:inc.map(fmt),outgoing:out.map(fmt)});
    }
    if(seg.length===2&&seg[1]==='find'&&m==='GET'){
      if(!await throttle(db,'ffind:'+u.id,60,600000)) return err('Слишком много поисков, подождите немного',429);
      const q=String(url.searchParams.get('q')||'').toLowerCase().replace(/[%_\\]/g,'').trim().slice(0,16); if(!q) return J({users:[]});
      const rs=(await db.prepare('SELECT id,name,role,look FROM users WHERE name_lc LIKE ? AND id<>? ORDER BY (name_lc=?) DESC,name_lc LIMIT 12').bind(q+'%',u.id,q).all()).results||[];
      const outl=[]; for(const r of rs) outl.push({...fmt(r),rel:await relOf(r.id)});
      return J({users:outl});
    }
    if(seg.length===2&&m==='POST'){
      const act=seg[1]; if(!['add','accept','decline','cancel','remove'].includes(act)) return err('Неизвестное действие',404);
      const b=await body(), id=String(b&&b.id||''); if(!ID_RE.test(id)) return err('Неверный id');
      if(id===u.id) return err('Это вы сами');
      if(!await db.prepare('SELECT 1 x FROM users WHERE id=?').bind(id).first()) return err('Игрок не найден',404);
      const r0=await relOf(id), now=Date.now();
      const makeFriends=async()=>{
        const c1=(await db.prepare('SELECT COUNT(*) c FROM friend WHERE a=?').bind(u.id).first()).c, c2=(await db.prepare('SELECT COUNT(*) c FROM friend WHERE a=?').bind(id).first()).c;
        if(c1>=200) return 'У вас уже 200 друзей (максимум)'; if(c2>=200) return 'У этого игрока уже максимум друзей';
        await db.batch([
          db.prepare('DELETE FROM freq WHERE (src=? AND dst=?) OR (src=? AND dst=?)').bind(u.id,id,id,u.id),
          db.prepare('INSERT OR IGNORE INTO friend(a,b,ts) VALUES(?,?,?)').bind(u.id,id,now),
          db.prepare('INSERT OR IGNORE INTO friend(a,b,ts) VALUES(?,?,?)').bind(id,u.id,now)
        ]); return null;
      };
      if(act==='add'){
        if(r0==='friend'||r0==='out') return J({ok:1,rel:r0});
        if(!await throttle(db,'freq:'+u.id,30,600000)) return err('Слишком много заявок, подождите немного',429);
        if(r0==='in'){ const e=await makeFriends(); return e?err(e):J({ok:1,rel:'friend'}); }
        const no=(await db.prepare('SELECT COUNT(*) c FROM freq WHERE src=?').bind(u.id).first()).c; if(no>=40) return err('Слишком много неотвеченных заявок (максимум 40)');
        await db.prepare('INSERT OR IGNORE INTO freq(src,dst,ts) VALUES(?,?,?)').bind(u.id,id,now).run(); return J({ok:1,rel:'out'});
      }
      if(act==='accept'){ if(r0!=='in') return err('Заявки нет',404); const e=await makeFriends(); return e?err(e):J({ok:1,rel:'friend'}); }
      if(act==='decline'){ await db.prepare('DELETE FROM freq WHERE src=? AND dst=?').bind(id,u.id).run(); return J({ok:1,rel:'none'}); }
      if(act==='cancel'){ await db.prepare('DELETE FROM freq WHERE src=? AND dst=?').bind(u.id,id).run(); return J({ok:1,rel:'none'}); }
      if(act==='remove'){ await db.batch([db.prepare('DELETE FROM friend WHERE a=? AND b=?').bind(u.id,id),db.prepare('DELETE FROM friend WHERE a=? AND b=?').bind(id,u.id)]); return J({ok:1,rel:'none'}); }
    }
  }

  /* ---- чат ---- */
  if(seg[0]==='chat'&&seg.length===2){
    const room=seg[1]; if(!ROOM_RE.test(room)) return err('Неверная комната');
    if(m==='GET'){
      const after=Math.max(0,parseInt(url.searchParams.get('after'))||0);
      const rs=(await db.prepare('SELECT id,user_id uid,name,text,ts FROM chat WHERE room=? AND id>? ORDER BY id DESC LIMIT ?').bind(room,after,after?50:30).all()).results||[];
      return J({messages:rs.reverse()});
    }
    if(m==='POST'){
      const b=await body(), text=cleanText(b&&b.text,140); if(!text) return err('Пустое сообщение');
      const last=await db.prepare('SELECT ts FROM chat WHERE user_id=? ORDER BY id DESC LIMIT 1').bind(u.id).first();
      if(last&&Date.now()-last.ts<1000) return err('Не так быстро',429);
      const ts=Date.now(), r=await db.prepare('INSERT INTO chat(room,user_id,name,text,ts) VALUES(?,?,?,?,?)').bind(room,u.id,u.name,text,ts).run();
      const id=r.meta.last_row_id;
      await db.prepare('DELETE FROM chat WHERE room=? AND id<?').bind(room,id-200).run();
      return J({message:{id,uid:u.id,name:u.name,text,ts}});
    }
  }

  /* ---- админка ---- */
  if(seg[0]==='admin'){
    if(u.role!=='admin') return err('Нет доступа',403);
    if(p==='admin/users'&&m==='GET'){
      const q=String(url.searchParams.get('q')||'').toLowerCase().replace(/[%_\\]/g,'').slice(0,16);
      const rs=(await db.prepare('SELECT id,name,role,created,ban_until,ban_reason,(SELECT COUNT(*) FROM games WHERE owner=users.id) gn FROM users WHERE name_lc LIKE ? ORDER BY created DESC LIMIT 100').bind('%'+q+'%').all()).results||[];
      return J({users:rs});
    }
    if(p==='admin/ban'&&m==='POST'){
      const b=await body(), id=String(b&&b.userId||''), hrs=+(b&&b.hours)||0, reason=cleanText(b&&b.reason,200);
      const t=await db.prepare('SELECT id,role FROM users WHERE id=?').bind(id).first();
      if(!t) return err('Игрок не найден',404); if(t.role==='admin') return err('Нельзя заблокировать админа');
      const until=hrs>0?Date.now()+Math.min(hrs,24*3650)*3600000:FOREVER;
      await db.prepare('UPDATE users SET ban_until=?,ban_reason=? WHERE id=?').bind(until,reason,id).run(); return J({ok:1});
    }
    if(p==='admin/unban'&&m==='POST'){
      const b=await body(); await db.prepare("UPDATE users SET ban_until=0,ban_reason='' WHERE id=?").bind(String(b&&b.userId||'')).run(); return J({ok:1});
    }
    if(p==='admin/chat'&&m==='GET'){
      const rs=(await db.prepare('SELECT id,room,user_id uid,name,text,ts FROM chat ORDER BY id DESC LIMIT 60').all()).results||[]; return J({messages:rs});
    }
    if(seg[1]==='chat'&&seg.length===3&&m==='DELETE'){ await db.prepare('DELETE FROM chat WHERE id=?').bind(parseInt(seg[2])||0).run(); return J({ok:1}); }
  }
  return err('Не найдено',404);
}

export default {
  async fetch(req,env){
    const url=new URL(req.url);
    if(!url.pathname.startsWith('/api/')){
      const res=await env.ASSETS.fetch(req);
      if(!(res.headers.get('Content-Type')||'').includes('text/html')) return res;
      /* Скрипты игр (Python) не могут обращаться к чужим сайтам: разрешены только наш сервер и CDN с Python */
      const h=new Headers(res.headers); h.set('Content-Security-Policy',"connect-src 'self' https://cdn.jsdelivr.net https://cloudflareinsights.com data: blob:");
      return new Response(res.body,{status:res.status,statusText:res.statusText,headers:h});
    }
    try{ return await api(req,env,url); }
    catch(e){ console.error(e); return err('Ошибка сервера',500); }
  }
};

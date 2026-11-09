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
  const row=await db.prepare('SELECT avatar FROM users WHERE id=?').bind(u.id).first();
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
const cleanText=(s,n)=>String(s==null?'':s).replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e]/g,' ').replace(/\s+/g,' ').trim().slice(0,n);

function thumbOf(g){
  const parts=(g.parts||[]).filter(p=>p&&p.type!=='coin'&&p.sx<150).slice(0,260).map(p=>({type:p.type,x:p.x,y:p.y,z:p.z,sx:p.sx,sy:p.sy,sz:p.sz,color:p.color,shape:p.shape,ry:p.ry}));
  return {cover:typeof g.cover==='string'&&g.cover.length<150000?g.cover:null,settings:{sky:g.settings&&g.settings.sky},parts};
}

async function api(req,env,url){
  const db=env.DB; if(!db) return err('База данных не подключена: добавьте привязку D1 с именем DB',500);
  const m=req.method, seg=url.pathname.slice(5).split('/').filter(Boolean).map(decodeURIComponent), p=seg.join('/');
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
    if(await db.prepare('SELECT 1 x FROM users WHERE name_lc=?').bind(lc).first()) return err('Такое имя уже занято',409);
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

  if(p==='me'&&m==='GET') return me(db,u,null);
  if(p==='logout'&&m==='POST'){ await db.prepare('DELETE FROM sessions WHERE token=?').bind(u.token).run(); return J({ok:1}); }

  if(seg[0]==='games'&&seg.length===2){
    const id=seg[1]; if(!ID_RE.test(id)) return err('Неверный id игры');
    if(m==='PUT'){
      const b=await body(), g=b&&b.game; if(!g||!Array.isArray(g.parts)||g.id!==id) return err('Неверные данные игры');
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
    const js=JSON.stringify(a); if(bytes(js)>LIM.avatar) return err('Аватар слишком большой',413);
    await db.prepare('UPDATE users SET avatar=? WHERE id=?').bind(js,u.id).run(); return J({ok:1});
  }

  /* ---- каталог игр ---- */
  if(seg[0]==='pub'){
    if(seg.length===1&&m==='GET'){
      const rs=(await db.prepare('SELECT p.id,p.name,p.descr,p.owner,x.name author,p.ts,p.plays,p.thumb,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id AND user_id=?) liked FROM pub p JOIN users x ON x.id=p.owner ORDER BY p.ts DESC LIMIT 40').bind(u.id).all()).results||[];
      return J({items:rs.map(r=>({id:r.id,name:r.name,desc:r.descr,authorId:r.owner,authorName:r.author,ts:r.ts,plays:r.plays,likes:r.likes,liked:!!r.liked,game:parse(r.thumb)||{parts:[]}}))});
    }
    if(seg.length===1&&m==='POST'){
      const b=await body(), g=b&&b.game; if(!g||!Array.isArray(g.parts)||!ID_RE.test(g.id||'')) return err('Неверные данные игры');
      const snd=Array.isArray(b.sounds)?b.sounds.filter(s=>s&&typeof s.id==='string'&&typeof s.data==='string'&&s.data.startsWith('data:audio')).map(s=>({id:s.id.slice(0,40),name:cleanText(s.name,40),data:s.data})):[];
      const gj=JSON.stringify(g), sj=JSON.stringify(snd);
      if(bytes(gj)>LIM.pubGame) return err('Игра слишком большая для публикации (максимум 0,9 МБ)',413);
      if(bytes(sj)>LIM.pubSounds) return err('Свои звуки в игре слишком большие для публикации (максимум 0,9 МБ)',413);
      const name=cleanText(g.name,40)||'Игра', desc=b.desc==null?null:cleanText(b.desc,500).slice(0,500), th=JSON.stringify(thumbOf(g));
      const ex=await db.prepare('SELECT owner FROM pub WHERE id=?').bind(g.id).first();
      if(ex){
        if(ex.owner!==u.id) return err('Эта игра принадлежит другому автору',403);
        await db.prepare('UPDATE pub SET name=?,json=?,sounds=?,thumb=?,descr=COALESCE(?,descr) WHERE id=?').bind(name,gj,sj,th,desc,g.id).run();
      }else{
        const n=(await db.prepare('SELECT COUNT(*) n FROM pub WHERE owner=?').bind(u.id).first()).n; if(n>=LIM.pubs) return err('Можно опубликовать не больше '+LIM.pubs+' игр',400);
        await db.prepare('INSERT INTO pub(id,owner,name,descr,json,sounds,thumb,ts,plays) VALUES(?,?,?,?,?,?,?,?,0)').bind(g.id,u.id,name,desc||'',gj,sj,th,Date.now()).run();
      }
      return J({ok:1});
    }
    const id=seg[1]; if(!id||!ID_RE.test(id)) return err('Неверный id',400);
    if(seg.length===2&&m==='GET'){
      const r=await db.prepare('SELECT p.*,x.name author,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE pub_id=p.id AND user_id=?) liked FROM pub p JOIN users x ON x.id=p.owner WHERE p.id=?').bind(u.id,id).first();
      if(!r) return err('Игра не найдена',404);
      return J({item:{id:r.id,name:r.name,desc:r.descr,authorId:r.owner,authorName:r.author,ts:r.ts,plays:r.plays,likes:r.likes,liked:!!r.liked,game:parse(r.json),sounds:parse(r.sounds)||[]}});
    }
    if(seg.length===2&&m==='PATCH'){
      const b=await body(); const r=await db.prepare('UPDATE pub SET descr=? WHERE id=? AND owner=?').bind(cleanText(b&&b.desc,500),id,u.id).run();
      return r.meta&&r.meta.changes?J({ok:1}):err('Нет доступа',403);
    }
    if(seg.length===2&&m==='DELETE'){
      const r=u.role==='admin'?await db.prepare('DELETE FROM pub WHERE id=?').bind(id).run():await db.prepare('DELETE FROM pub WHERE id=? AND owner=?').bind(id,u.id).run();
      if(!(r.meta&&r.meta.changes)) return err('Нет доступа',403);
      await db.prepare('DELETE FROM likes WHERE pub_id=?').bind(id).run(); return J({ok:1});
    }
    if(seg.length===3&&seg[2]==='like'&&m==='POST'){
      if(!await db.prepare('SELECT 1 x FROM pub WHERE id=?').bind(id).first()) return err('Игра не найдена',404);
      const d=await db.prepare('DELETE FROM likes WHERE pub_id=? AND user_id=?').bind(id,u.id).run(); let liked=false;
      if(!(d.meta&&d.meta.changes)){ await db.prepare('INSERT OR IGNORE INTO likes(pub_id,user_id) VALUES(?,?)').bind(id,u.id).run(); liked=true; }
      const c=(await db.prepare('SELECT COUNT(*) n FROM likes WHERE pub_id=?').bind(id).first()).n; return J({liked,count:c});
    }
    if(seg.length===3&&seg[2]==='play'&&m==='POST'){ await db.prepare('UPDATE pub SET plays=plays+1 WHERE id=?').bind(id).run(); return J({ok:1}); }
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
    if(!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try{ return await api(req,env,url); }
    catch(e){ console.error(e); return err('Ошибка сервера',500); }
  }
};

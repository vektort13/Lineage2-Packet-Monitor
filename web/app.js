'use strict';
const $ = id => document.getElementById(id);
const state = {token:'', cursor:0, categorySelection:null, typeSelection:null, types:[], paused:false, rows:0, selected:null, editorSource:null, categories:[], activeTab:'fields', editorMode:'hex-to-text'};
try{const saved=JSON.parse(localStorage.getItem('l2-packet-filters')||'{}');if(Array.isArray(saved.categories))state.categorySelection=new Set(saved.categories);if(Array.isArray(saved.types))state.typeSelection=new Set(saved.types);}catch{}
function saveFilters(){localStorage.setItem('l2-packet-filters',JSON.stringify({categories:state.categorySelection===null?null:[...state.categorySelection],types:state.typeSelection===null?null:[...state.typeSelection]}));}
const number = value => Number(value || 0).toLocaleString('ru-RU');
async function api(path, body){
  const response = await fetch(path, body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-Monitor-Token':state.token}, body:JSON.stringify(body)});
  const data = await response.json();
  if(!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
let toastTimer;
function toast(message){ $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('toast').hidden=true,4500); }
function showTab(tab){state.activeTab=tab; $('fieldsView').hidden=tab!=='fields'; $('editorView').hidden=tab!=='editor'; $('fieldsTab').classList.toggle('active',tab==='fields'); $('editorTab').classList.toggle('active',tab==='editor');}
let filterGeneration=0;
function resetList(){filterGeneration++;state.cursor=0; state.rows=0; $('packets').replaceChildren(); $('empty').hidden=false; $('visibleCount').textContent='0';}
let libraryRefresh=0;
let sending=false;
async function refreshSender(){const s=await api('/api/sender');$('sendPacket').disabled=sending||!s.available||s.pending||state.editorSource?.direction==='server';if(!s.available){$('sendStatus').textContent=s.reason||'Отправка не подключена';return;}const last=s.history.at(-1);if(last)$('sendStatus').textContent=last.wire_verified?`Отправка подтверждена захватом · пакет #${last.packet_id}`:'Штатный вызов завершён · ожидание пакета в захвате';}
async function refreshLibrary(){
  const query=new URLSearchParams();if($('libraryKind').value)query.set('kind',$('libraryKind').value);if($('librarySearch').value)query.set('search',$('librarySearch').value);if($('libraryServer').value)query.set('server',$('libraryServer').value);
  const data=await api('/api/library?'+query);$('libraryCount').textContent=number(data.count);$('libraryEmpty').hidden=data.count>0;
  $('libraryRows').replaceChildren(...data.entries.slice(0,1000).map(e=>{const tr=document.createElement('tr');tr.style.setProperty('--category',e.kind==='skill'?'#f0883e':'#e3b341');tr.title=e.profile;tr.append(cell(e.kind==='item'?'Предмет':'Умение'),cell(e.entity_id),cell(e.kind==='skill'?e.level:'—'),cell(e.name||'—'),cell(e.server+' · '+e.profile),cell(number(e.observations)),cell(new Date(e.last_seen).toLocaleString('ru-RU')));return tr;}));
  $('libraryJson').href='/api/library/export?'+query;query.set('format','csv');$('libraryCsv').href='/api/library/export?'+query;
}
function renderCategories(counts={}){
  const categories=state.categories.filter(c=>c.id!=='compressed');
  const all=[{id:'',label:'Все',color:'#8d9bb0'},...categories];
  $('categories').replaceChildren(...all.map(c=>{const label=document.createElement('label'),input=document.createElement('input'),text=document.createElement('span');input.type='checkbox';input.checked=c.id?(state.categorySelection===null||state.categorySelection.has(c.id)):(state.categorySelection===null||state.categorySelection.size===categories.length);if(!c.id&&state.categorySelection?.size)input.indeterminate=state.categorySelection.size<categories.length;label.className='chip'+(input.checked?' active':'');label.style.setProperty('--category',c.color);text.textContent=c.label+(counts[c.id]?' '+number(counts[c.id]):'');label.append(input,text);input.onchange=()=>{if(!c.id)state.categorySelection=input.checked?null:new Set();else{if(state.categorySelection===null)state.categorySelection=new Set(categories.map(x=>x.id));if(input.checked)state.categorySelection.add(c.id);else state.categorySelection.delete(c.id);}saveFilters();resetList();renderCategories(counts);};return label;}));
}
function renderTypes(){
  const search=$('typeSearch').value.toLowerCase();
  $('typeSummary').textContent=state.typeSelection===null?`Типы пакетов · все (${state.types.length})`:`Типы пакетов · выбрано ${state.typeSelection.size}`;
  $('packetTypes').replaceChildren(...state.types.filter(t=>(t.name+' '+t.opcode+' '+t.direction).toLowerCase().includes(search)).map(t=>{const label=document.createElement('label'),input=document.createElement('input'),name=document.createElement('span');input.type='checkbox';input.checked=state.typeSelection===null||state.typeSelection.has(t.id);label.style.setProperty('--category',t.color);name.textContent=`${t.direction==='server'?'S→C':'C→S'} ${t.opcode} ${t.name} (${number(t.count)})`;label.append(input,name);input.onchange=()=>{if(state.typeSelection===null)state.typeSelection=new Set(state.types.map(x=>x.id));if(input.checked)state.typeSelection.add(t.id);else state.typeSelection.delete(t.id);saveFilters();resetList();renderTypes();};return label;}));
}
function renderItems(data){
  $('nearbyCount').textContent=data.items.length; $('itemsEmpty').hidden=data.items.length>0;
  $('ownPosition').textContent=data.own_position?'Позиция: '+data.own_position.join(', '):'Позиция ещё не получена';
  $('nearbyItems').replaceChildren(...data.items.slice(0,300).map(i=>{const tr=document.createElement('tr');tr.style.setProperty('--category',i.state==='present'?'#e3b341':'#6e7681');tr.append(cell(i.object_id),cell(i.template_value??'—'),cell(i.amount===null?'—':number(i.amount)),cell(i.xyz?.join(', ')||'—'),cell(i.distance_xy??'—'),cell(i.state==='present'?'Описан':'Нужно обновление'));tr.onclick=()=>{$('search').value=String(i.object_id);resetList();window.scrollTo({top:0,behavior:'smooth'});};return tr;}));
  $('itemEvents').replaceChildren(...data.events.slice(0,12).map(e=>{const div=document.createElement('div');div.className='item-event';const strong=document.createElement('strong'),small=document.createElement('small');strong.textContent=e.label;small.textContent=`${e.object_id} · Item ${e.template_value??'—'} · ×${e.amount??'—'}`;div.append(strong,small);return div;}));
  if(!data.events.length)$('itemEvents').textContent='Ожидание событий';
}
function renderStatus(s){
  const labels={live:'LIVE', stopped:'Остановлен', waiting:'Ожидание', discovering:'Поиск процесса', synchronizing:'Синхронизация'};
  $('connection').textContent=labels[s.state]||s.state;
  $('connection').className='status-pill '+(s.state==='live'?'live':s.running?'waiting':'');
  $('total').textContent=number(s.packets.total); $('serverCount').textContent=number(s.packets.directions.server); $('clientCount').textContent=number(s.packets.directions.client);
  $('compressedCount').textContent=number(s.compressed_blocks); $('expandedCount').textContent=number(s.expanded_bytes)+' байт распаковано'; $('windowsCount').textContent=number(s.validated_windows);
  $('start').disabled=s.running; $('stop').disabled=!s.running;
  $('liveMessage').textContent=s.message;
  if(s.endpoint) $('endpoint').textContent=`PID ${s.process.pid} · ${s.endpoint.remote_ip}:${s.endpoint.remote_port}`;
  $('processInfo').textContent=s.process?`${s.process.name} · PID ${s.process.pid} · ${s.interface?.name||''}`:'Локальный монитор · 127.0.0.1';
  $('syncInfo').textContent=`Шифр: ${s.detected_cipher||s.requested_cipher||'авто'} · ${s.interval_seconds}–${Math.ceil(s.interval_seconds+2)} с · синхронизации: ${s.sync_errors}`;
  $('historyInfo').textContent=`В памяти ${number(s.packets.retained)} / ${number(s.packets.capacity)} пакетов`;
  renderCategories(s.packets.categories);
}
function cell(text, cls){const td=document.createElement('td'); td.textContent=text; if(cls)td.className=cls; return td;}
function renderPackets(packets){
  for(const p of packets){
    const row=document.createElement('tr'); row.dataset.id=p.id; row.style.setProperty('--category',p.color);
    const t=new Date(p.time).toLocaleTimeString('ru-RU',{hour12:false})+'.'+p.time.slice(20,23);
    row.append(cell(p.id),cell(t),cell(p.direction==='server'?'S → C':'C → S','direction '+p.direction),cell(p.opcode));
    const name=cell(p.name); if(p.compressed){const mark=document.createElement('span'); mark.className='compressed-mark'; mark.textContent='Z'; mark.title='Распакован из DEFLATE'; name.append(mark);} row.append(name,cell(p.length));
    const tag=cell(''); const badge=document.createElement('span'); badge.className='badge'; badge.textContent=p.category_label; tag.append(badge); row.append(tag);
    row.onclick=()=>openPacket(p.id); if(state.selected?.id===p.id)row.classList.add('selected');
    $('packets').prepend(row); state.rows++;
  }
  while($('packets').children.length>1200){$('packets').lastElementChild.remove(); state.rows--;}
  $('empty').hidden=state.rows>0; $('visibleCount').textContent=number(state.rows);
}
async function openPacket(id){
  try{
    const p=await api('/api/packets/'+id); state.selected=p;
    document.querySelectorAll('#packets tr').forEach(row=>row.classList.toggle('selected',Number(row.dataset.id)===id));
    $('detailTitle').textContent=p.name; $('detailSubtitle').textContent=`#${p.id} · ${p.direction==='server'?'Сервер → клиент':'Клиент → сервер'} · ${p.opcode}`; $('detailEmpty').hidden=true;
    const pairs=[['Категория',p.category_label],['Размер',p.length+' байт'],['Шифр',p.cipher_variant||p.cipher||'—'],['Сжатие',p.compressed?'DEFLATE · распакован':'Нет'],['Кадр',p.frame],['SHA-256',p.sha256]];
    $('detailMeta').replaceChildren(...pairs.flatMap(([key,value])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=key;dd.textContent=value;return [dt,dd];}));
    $('fields').textContent=Object.keys(p.fields).length?JSON.stringify(p.fields,null,2):'Поля этого пакета пока не описаны.';
    if(p.schema_error)$('fields').textContent+='\n\n'+p.schema_error;
    $('editCopy').hidden=false; showTab('fields');
  }catch(error){toast(error.message);}
}
function editorError(error){$('editorError').textContent=error?.message||''; $('editorError').hidden=!error;}
function updateEditor(result, replaceHex=true){
  if(replaceHex)$('hex').value=result.hex; $('text').value=result.text;
  $('editorInfo').textContent=`${number(result.length)} байт · u16: ${result.declared_length??'—'} · ${result.length_matches?'длина совпадает':'длина отличается'} · обратимо`;
  state.editorMode='hex-to-text'; editorError(null);
}
async function convert(mode='hex-to-text', updateLength=false){
  try{
    const result=await api('/api/convert',{mode, hex:$('hex').value, text:$('text').value,encoding:$('encoding').value,update_length:updateLength});
    updateEditor(result); return result;
  }catch(error){editorError(error);return null;}
}
async function editCopy(){
  if(!state.selected)return;
  state.editorSource=state.selected; $('hex').value=state.selected.raw_hex; $('editorSource').textContent='Копия пакета #'+state.selected.id;
  $('draftStatus').textContent=''; $('downloadDraft').hidden=true; showTab('editor'); await convert();
}
async function refreshDiscovery(){
  $('refresh').disabled=true;
  try{
    const [p,n]=await Promise.all([api('/api/processes'),api('/api/interfaces')]);
    const pid=$('process').value, iface=$('interface').value;
    $('process').replaceChildren(new Option('Автоматически',''),...p.processes.map(p=>new Option(`${p.name} · PID ${p.pid}`,p.pid)));
    $('interface').replaceChildren(new Option('Автоматически','auto'),...n.interfaces.map(i=>new Option(i.name+(i.recommended?' · физический':''),i.id)));
    if([...$('process').options].some(o=>o.value===pid))$('process').value=pid;
    if([...$('interface').options].some(o=>o.value===iface))$('interface').value=iface;
  }catch(error){toast(error.message);}finally{$('refresh').disabled=false;}
}
async function poll(){
  try{
    renderStatus(await api('/api/status'));
    if(!state.paused){
      const query=new URLSearchParams({after:String(state.cursor),limit:'500'});
      if(state.categorySelection!==null)query.set('categories',[...state.categorySelection].join(','));if(state.typeSelection!==null)query.set('types',[...state.typeSelection].join(',')); if($('direction').value)query.set('direction',$('direction').value); if($('search').value)query.set('search',$('search').value);
      const generation=filterGeneration;const page=await api('/api/packets?'+query);if(generation===filterGeneration){state.cursor=page.cursor;renderPackets(page.packets);}
      if(page.history_truncated)toast('Старые записи вышли за пределы буфера.');
    }
    renderItems(await api('/api/items'));
    state.types=(await api('/api/types')).types;renderTypes();
    if(libraryRefresh++%4===0)await refreshLibrary();
    await refreshSender();
  }catch(error){$('connection').textContent='API недоступен'; $('connection').className='status-pill waiting'; $('liveMessage').textContent=error.message;}
  setTimeout(poll,1000);
}
$('fieldsTab').onclick=()=>showTab('fields'); $('editorTab').onclick=()=>showTab('editor'); $('editCopy').onclick=editCopy;
$('newBuffer').onclick=()=>{state.editorSource=null; state.editorMode='hex-to-text'; $('hex').value=''; $('text').value=''; $('editorSource').textContent='Локальный буфер'; $('editorInfo').textContent='0 байт'; $('draftStatus').textContent=''; $('downloadDraft').hidden=true; editorError(null); showTab('editor');};
$('hex').oninput=()=>{state.editorMode='hex-to-text'; $('downloadDraft').hidden=true; $('draftStatus').textContent='Изменённый буфер';};
$('text').oninput=()=>{state.editorMode='text-to-hex';$('downloadDraft').hidden=true;$('draftStatus').textContent='Текст изменён';};
$('toText').onclick=()=>convert(); $('toHex').onclick=()=>convert('text-to-hex'); $('fixLength').onclick=()=>convert(state.editorMode,true); $('encoding').onchange=()=>convert(state.editorMode);
$('saveDraft').onclick=async()=>{try{if(!await convert(state.editorMode))return;const result=await api('/api/drafts',{hex:$('hex').value,encoding:$('encoding').value,packet_id:state.editorSource?.id});updateEditor(result);$('draftStatus').textContent=`Черновик ${result.id.slice(0,8)} сохранён`+(result.changed_bytes===null?'':` · изменено ${result.changed_bytes} байт`);$('downloadDraft').href='/api/drafts/'+result.id+'.bin';$('downloadDraft').hidden=false;}catch(error){editorError(error);}};
$('sendPacket').onclick=async()=>{if(sending)return;sending=true;$('sendPacket').disabled=true;try{if(!await convert(state.editorMode))return;const result=await api('/api/send',{hex:$('hex').value,packet_id:state.editorSource?.id});$('sendStatus').textContent='Штатный вызов завершён · ожидание подтверждения захвата';toast(`Вызов клиента завершён: ${result.length} байт · ${result.opcode}`);}catch(error){editorError(error);}finally{sending=false;refreshSender().catch(e=>editorError(e));}};
$('start').onclick=async()=>{try{await api('/api/start',{pid:$('process').value?Number($('process').value):null,interface:$('interface').value,cipher:$('cipher').value});toast('Поиск процесса и запуск захвата');}catch(error){toast(error.message);}};
$('cipher').onchange=async()=>{try{$('cipher').disabled=true;await api('/api/cipher',{cipher:$('cipher').value});toast('Режим шифрования применён');}catch(error){toast(error.message);}finally{$('cipher').disabled=false;}};
$('stop').onclick=async()=>{try{$('stop').disabled=true;await api('/api/stop',{});toast('Захват остановлен');}catch(error){toast(error.message);}};
$('pause').onclick=()=>{state.paused=!state.paused;$('pause').textContent=state.paused?'▶ Продолжить список':'Ⅱ Пауза списка';};
$('refresh').onclick=refreshDiscovery; $('direction').onchange=resetList;
$('typeSearch').oninput=renderTypes;$('allTypes').onclick=()=>{state.typeSelection=null;saveFilters();resetList();renderTypes();};$('noTypes').onclick=()=>{state.typeSelection=new Set();saveFilters();resetList();renderTypes();};
let searchTimer; $('search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(resetList,250);};
let libraryTimer;$('libraryKind').onchange=()=>refreshLibrary().catch(e=>toast(e.message));for(const id of ['librarySearch','libraryServer'])$(id).oninput=()=>{clearTimeout(libraryTimer);libraryTimer=setTimeout(()=>refreshLibrary().catch(e=>toast(e.message)),250);};
(async()=>{try{const info=await api('/api/info');state.token=info.token;state.categories=info.categories;$('cipher').replaceChildren(...info.ciphers.map(c=>new Option(c.name,c.id)));renderCategories();refreshDiscovery();poll();}catch(error){toast(error.message);}})();

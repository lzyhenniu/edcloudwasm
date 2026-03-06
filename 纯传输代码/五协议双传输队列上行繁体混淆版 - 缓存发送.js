import {connect as 建立雲端連線} from 'cloudflare:sockets';
const 使用者識別碼 = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const 密碼雜湊值 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const 代理使用者名稱 = 'admin';
const 代理使用者密碼 = '123456';
const 緩衝區大小 = 512 * 1024;
const 啟動閾值 = 50 * 1024 * 1024;
const 最大區塊長度 = 64 * 1024;
const 刷新時間 = 20;
const 僅網域並發 = false;
let 並發數量 = 4;
const 代理策略順序 = ['socks', 'http', 'nat64'];
const 加密網域端點列表 = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const 加密網域轉換端點列表 = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const 代理位址表 = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const 最終代理主機 = 'ProxyIP.CMLiussss.net';
const 機房區域對照 = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const 機房到代理映射 = new Map();
for (const [區域代號, 機房集合] of Object.entries(機房區域對照)) {for (const 機房代號 of 機房集合) 機房到代理映射.set(機房代號, 代理位址表[區域代號])}
const 識別碼位元組 = new Uint8Array(16), 雜湊位元組 = new Uint8Array(56), 偏移陣列 = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let 索引 = 0, 暫存值; 索引 < 16; 索引++) 識別碼位元組[索引] = (((暫存值 = 使用者識別碼.charCodeAt(索引 * 2 + 偏移陣列[索引])) > 64 ? 暫存值 + 9 : 暫存值) & 0xF) << 4 | (((暫存值 = 使用者識別碼.charCodeAt(索引 * 2 + 偏移陣列[索引] + 1)) > 64 ? 暫存值 + 9 : 暫存值) & 0xF);
for (let 索引 = 0; 索引 < 56; 索引++) 雜湊位元組[索引] = 密碼雜湊值.charCodeAt(索引);
const [文字編碼器, 文字解碼器, 通道五初始化封包, 通道五回應封包] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2]), new Uint8Array([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])];
let 通道五認證封包, 超文本授權值;
const 超文本連線成功回應 = 文字編碼器.encode("HTTP/1.1 200 Connection Established\r\n\r\n"), 超文本認證失敗回應 = 文字編碼器.encode("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
if (代理使用者名稱 && 代理使用者密碼) {
    超文本授權值 = 文字編碼器.encode(btoa(`${代理使用者名稱}:${代理使用者密碼}`));
    const 使用者位元組 = 文字編碼器.encode(代理使用者名稱), 密碼位元組 = 文字編碼器.encode(代理使用者密碼);
    通道五認證封包 = new Uint8Array(3 + 使用者位元組.length + 密碼位元組.length);
    通道五認證封包[0] = 1, 通道五認證封包[1] = 使用者位元組.length, 通道五認證封包.set(使用者位元組, 2), 通道五認證封包[2 + 使用者位元組.length] = 密碼位元組.length, 通道五認證封包.set(密碼位元組, 3 + 使用者位元組.length);
}
const 首頁內容 = `<body style=margin:0;overflow:hidden;background:#000><canvas id=c style=width:100vw;height:100vh><script>var C=document.getElementById("c"),g=C.getContext("webgl"),t=0,P,R,F,U,O,X,Y,L,T,b=.4,K="float L(vec3 v){vec3 a=v;float b,c,d;for(int i=0;i<5;i++){b=length(a);c=atan(a.y,a.x)*10.;d=acos(a.z/b)*10.;b=pow(b,8.);a=vec3(b*sin(d)*cos(c),b*sin(d)*sin(c),b*cos(d))+v;if(b>6.)break;}return 4.-dot(a,a);}",VS="attribute vec4 p;varying vec3 d,ld;uniform vec3 r,f,u;uniform float x,y;void main(){gl_Position=p;d=f+r*p.x*x+u*p.y*y;ld=vec3(p.x*x,p.y*y,-1.);}",FS="precision highp float;float L(vec3 v);uniform vec3 r,f,u,o;uniform float t;varying vec3 d,ld;uniform float l;void main(){vec3 tc=vec3(0);for(int i=0;i<4;i++){vec2 of=vec2(mod(float(i),2.),floor(float(i)/2.))*.5;vec3 rd=normalize(d+r*of.x*.001+u*of.y*.001),c=vec3(0);float s=.002*l,r1,r2,r3;for(int k=2;k<1200;k++){float ds=s*float(k);vec3 p=o+rd*ds;if(L(p)>0.){r1=s*float(k-1);r2=ds;for(int j=0;j<24;j++){r3=(r1+r2)*.5;if(L(o+rd*r3)>0.)r2=r3;else r1=r3;}vec3 v=o+rd*r3,nw;float e=r3*1e-4;nw=normalize(vec3(L(v-r*e)-L(v+r*e),L(v-u*e)-L(v+u*e),L(v+f*e)-L(v-f*e)));vec3 rf=reflect(normalize(ld),nw);float d2=dot(v,v),lt=pow(max(0.,dot(rf,vec3(.276,.92,.276))),4.)*.45+max(0.,dot(nw,vec3(.276,.92,.276)))*.25+.3;c=(sin(d2*5.+t+vec3(0,2,4))*.5+.5)*lt;break;}}tc+=c;}gl_FragColor=vec4(pow(tc*.25,vec3(.7)),1);}";function i(){var s=g.createProgram(),v=g.createShader(35633),f=g.createShader(35632);g.shaderSource(v,VS),g.compileShader(v),g.shaderSource(f,FS+K),g.compileShader(f),g.attachShader(s,v),g.attachShader(s,f),g.linkProgram(s),g.useProgram(s),P=g.getAttribLocation(s,"p"),R=g.getUniformLocation(s,"r"),F=g.getUniformLocation(s,"f"),U=g.getUniformLocation(s,"u"),O=g.getUniformLocation(s,"o"),X=g.getUniformLocation(s,"x"),Y=g.getUniformLocation(s,"y"),L=g.getUniformLocation(s,"l"),T=g.getUniformLocation(s,"t"),g.bindBuffer(34962,g.createBuffer()),g.bufferData(34962,new Float32Array([-1,-1,0,1,-1,0,1,1,0,-1,-1,0,1,1,0,-1,1,0]),35044),g.vertexAttribPointer(P,3,5126,!1,0,0),g.enableVertexAttribArray(P)}function w(){t+=.02,innerWidth*devicePixelRatio!=C.width&&(C.width=innerWidth*(d=devicePixelRatio||1),C.height=innerHeight*d,g.viewport(0,0,C.width,C.height));var v=C.width/C.height;g.uniform1f(X,v>1?v:1),g.uniform1f(Y,v>1?1:1/v),g.uniform1f(L,1.6),g.uniform1f(T,t),g.uniform3f(O,1.6*Math.cos(t*.5)*Math.cos(b),1.6*Math.sin(b),1.6*Math.sin(t*.5)*Math.cos(b)),g.uniform3f(R,Math.sin(t*.5),0,-Math.cos(t*.5)),g.uniform3f(U,-Math.sin(b)*Math.cos(t*.5),Math.cos(b),-Math.sin(b)*Math.sin(t*.5)),g.uniform3f(F,-Math.cos(t*.5)*Math.cos(b),-Math.sin(b),-Math.sin(t*.5)*Math.cos(b)),g.drawArrays(4,0,6),requestAnimationFrame(w)}i(),w()</script>`;
const 二進位位址轉字串 = (位址類型, 位址位元組) => {
    if (位址類型 === 3) return 文字解碼器.decode(位址位元組);
    if (位址類型 === 1) return `${位址位元組[0]}.${位址位元組[1]}.${位址位元組[2]}.${位址位元組[3]}`;
    let 第六版位址字串 = ((位址位元組[0] << 8) | 位址位元組[1]).toString(16);
    for (let 索引 = 1; 索引 < 8; 索引++) 第六版位址字串 += ':' + ((位址位元組[索引 * 2] << 8) | 位址位元組[索引 * 2 + 1]).toString(16);
    return `[${第六版位址字串}]`;
};
const 解析主機連接埠 = (位址字串, 預設連接埠) => {
    let 主機 = 位址字串, 連接埠 = 預設連接埠, 索引位置;
    if (位址字串.charCodeAt(0) === 91) {
        if ((索引位置 = 位址字串.indexOf(']:')) !== -1) {
            主機 = 位址字串.substring(0, 索引位置 + 1);
            連接埠 = 位址字串.substring(索引位置 + 2);
        }
    } else if ((索引位置 = 位址字串.indexOf('.tp')) !== -1 && 位址字串.lastIndexOf(':') === -1) {
        連接埠 = 位址字串.substring(索引位置 + 3, 位址字串.indexOf('.', 索引位置 + 3));
    } else if ((索引位置 = 位址字串.lastIndexOf(':')) !== -1) {
        主機 = 位址字串.substring(0, 索引位置);
        連接埠 = 位址字串.substring(索引位置 + 1);
    }
    return [主機, (連接埠 = parseInt(連接埠), isNaN(連接埠) ? 預設連接埠 : 連接埠)];
};
const 解析認證字串 = (認證參數) => {
    let 使用者名稱, 密碼, 主機字串;
    const 艾特位置 = 認證參數.lastIndexOf('@');
    if (艾特位置 === -1) {主機字串 = 認證參數} else {
        const 認證片段 = 認證參數.substring(0, 艾特位置);
        主機字串 = 認證參數.substring(艾特位置 + 1);
        const 冒號位置 = 認證片段.indexOf(':');
        if (冒號位置 === -1) {使用者名稱 = 認證片段} else {
            使用者名稱 = 認證片段.substring(0, 冒號位置);
            密碼 = 認證片段.substring(冒號位置 + 1);
        }
    }
    const [主機名稱, 連接埠] = 解析主機連接埠(主機字串, 1080);
    return {使用者名稱, 密碼, 主機名稱, 連接埠};
};
const 是否為第四版位址 = (字串) => {
    const 長度 = 字串.length;
    if (長度 > 15 || 長度 < 7) return false;
    let 區段值 = 0, 點數量 = 0, 區段長度 = 0, 首字元 = 0;
    for (let 索引 = 0; 索引 < 長度; 索引++) {
        const 字元碼 = 字串.charCodeAt(索引);
        if (字元碼 === 46) {
            if (點數量 === 3 || 區段長度 === 0 || (區段長度 > 1 && 首字元 === 48)) return false;
            點數量++, 區段值 = 0, 區段長度 = 0;
        } else {
            const 數字值 = (字元碼 - 48) >>> 0;
            if (數字值 > 9) return false;
            if (區段長度 === 0) 首字元 = 字元碼;
            區段長度++, 區段值 = 區段值 * 10 + 數字值;
            if (區段值 > 255 || 區段長度 > 3) return false;
        }
    }
    return 點數量 === 3 && 區段長度 > 0 && !(區段長度 > 1 && 首字元 === 48);
};
const 是否為網域名稱 = (字串) => {
    if (!僅網域並發) return true;
    const 首碼 = 字串.charCodeAt(0);
    if ((首碼 - 48) >>> 0 > 9) return 首碼 !== 91;
    return !是否為第四版位址(字串);
};
const 建立單次連線 = (主機名稱, 連接埠, 連線插槽 = 建立雲端連線({hostname: 主機名稱, port: 連接埠})) => 連線插槽.opened.then(() => 連線插槽);
const 並發建立連線 = (主機名稱, 連接埠, 位址類型, 限制數量 = 並發數量) => {
    if (限制數量 === 1 || (僅網域並發 && 位址類型 !== 3)) return 建立單次連線(主機名稱, 連接埠);
    return Promise.any(Array(限制數量).fill(null).map(() => 建立單次連線(主機名稱, 連接埠)));
};
const 經通道代理連線 = async (目標位址類型, 目標連接埠數值, 通道認證資訊, 位址位元組, 限制數量) => {
    const 位址類型 = 是否為網域名稱(通道認證資訊.主機名稱) ? 3 : 0;
    const 通道連線插槽 = await 並發建立連線(通道認證資訊.主機名稱, 通道認證資訊.連接埠, 位址類型, 限制數量);
    const 寫入器 = 通道連線插槽.writable.getWriter();
    const 讀取器 = 通道連線插槽.readable.getReader();
    await 寫入器.write(通道五初始化封包);
    const {value: 認證回應} = await 讀取器.read();
    if (!認證回應 || 認證回應[0] !== 5 || 認證回應[1] === 0xFF) return null;
    if (認證回應[1] === 2) {
        if (!通道認證資訊.使用者名稱) return null;
        const 使用者位元組 = 文字編碼器.encode(通道認證資訊.使用者名稱);
        const 密碼位元組 = 文字編碼器.encode(通道認證資訊.密碼 || '');
        const 使用者長度 = 使用者位元組.length, 密碼長度 = 密碼位元組.length, 認證請求 = new Uint8Array(3 + 使用者長度 + 密碼長度)
        認證請求[0] = 1, 認證請求[1] = 使用者長度, 認證請求.set(使用者位元組, 2), 認證請求[2 + 使用者長度] = 密碼長度, 認證請求.set(密碼位元組, 3 + 使用者長度);
        await 寫入器.write(認證請求);
        const {value: 認證結果} = await 讀取器.read();
        if (!認證結果 || 認證結果[0] !== 1 || 認證結果[1] !== 0) return null;
    } else if (認證回應[1] !== 0) {return null}
    const 是否網域 = 目標位址類型 === 3, 通道請求封包 = new Uint8Array(6 + 位址位元組.length + (是否網域 ? 1 : 0));
    通道請求封包[0] = 5, 通道請求封包[1] = 1, 通道請求封包[2] = 0, 通道請求封包[3] = 目標位址類型;
    是否網域 ? (通道請求封包[4] = 位址位元組.length, 通道請求封包.set(位址位元組, 5)) : 通道請求封包.set(位址位元組, 4);
    通道請求封包[通道請求封包.length - 2] = 目標連接埠數值 >> 8, 通道請求封包[通道請求封包.length - 1] = 目標連接埠數值 & 0xff;
    await 寫入器.write(通道請求封包);
    const {value: 最終回應} = await 讀取器.read();
    if (!最終回應 || 最終回應[1] !== 0) return null;
    寫入器.releaseLock(), 讀取器.releaseLock();
    return 通道連線插槽;
};
const 固定超文本標頭 = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const 已編碼固定標頭 = 文字編碼器.encode(固定超文本標頭);
const 經超文本代理連線 = async (目標位址類型, 目標連接埠數值, 超文本認證資訊, 位址位元組, 限制數量) => {
    const {使用者名稱, 密碼, 主機名稱, 連接埠} = 超文本認證資訊;
    const 位址類型 = 是否為網域名稱(主機名稱) ? 3 : 0;
    const 代理連線插槽 = await 並發建立連線(主機名稱, 連接埠, 位址類型, 限制數量);
    const 寫入器 = 代理連線插槽.writable.getWriter();
    const 超文本主機 = 二進位位址轉字串(目標位址類型, 位址位元組);
    let 動態標頭 = `CONNECT ${超文本主機}:${目標連接埠數值} HTTP/1.1\r\nHost: ${超文本主機}:${目標連接埠數值}\r\n`;
    if (使用者名稱) 動態標頭 += `Proxy-Authorization: Basic ${btoa(`${使用者名稱}:${密碼 || ''}`)}\r\n`;
    const 完整標頭 = new Uint8Array(動態標頭.length * 3 + 已編碼固定標頭.length);
    const {written: 已寫入長度} = 文字編碼器.encodeInto(動態標頭, 完整標頭);
    完整標頭.set(已編碼固定標頭, 已寫入長度);
    await 寫入器.write(完整標頭.subarray(0, 已寫入長度 + 已編碼固定標頭.length));
    寫入器.releaseLock();
    const 讀取器 = 代理連線插槽.readable.getReader();
    const 暫存緩衝區 = new Uint8Array(512);
    let 已讀位元組 = 0, 狀態已檢查 = false;
    while (已讀位元組 < 暫存緩衝區.length) {
        const {value: 讀取值, done: 是否完成} = await 讀取器.read();
        if (是否完成 || 已讀位元組 + 讀取值.length > 暫存緩衝區.length) return null;
        const 先前已讀位元組 = 已讀位元組;
        暫存緩衝區.set(讀取值, 已讀位元組);
        已讀位元組 += 讀取值.length;
        if (!狀態已檢查 && 已讀位元組 >= 12) {
            if (暫存緩衝區[9] !== 50) return null;
            狀態已檢查 = true;
        }
        let 索引 = Math.max(15, 先前已讀位元組 - 3);
        while ((索引 = 暫存緩衝區.indexOf(13, 索引)) !== -1 && 索引 <= 已讀位元組 - 4) {
            if (暫存緩衝區[索引 + 1] === 10 && 暫存緩衝區[索引 + 2] === 13 && 暫存緩衝區[索引 + 3] === 10) {
                讀取器.releaseLock();
                return 代理連線插槽;
            }
            索引++;
        }
    }
    return null;
};
const 解析位址資料 = (暫存緩衝區, 偏移量, 位址類型) => {
    const 位址長度 = 位址類型 === 3 ? 暫存緩衝區[偏移量++] : 位址類型 === 1 ? 4 : 位址類型 === 4 ? 16 : null;
    if (位址長度 === null) return null;
    const 資料偏移 = 偏移量 + 位址長度;
    if (資料偏移 > 暫存緩衝區.length) return null;
    const 位址位元組 = 暫存緩衝區.subarray(偏移量, 資料偏移);
    return {位址位元組, 資料偏移};
};
const 解析請求封包 = (首區塊) => {
    for (let 索引 = 0; 索引 < 16; 索引++) if (首區塊[索引 + 1] !== 識別碼位元組[索引]) return null;
    let 偏移量 = 19 + 首區塊[17];
    const 連接埠 = (首區塊[偏移量] << 8) | 首區塊[偏移量 + 1];
    let 位址類型 = 首區塊[偏移量 + 2];
    if (位址類型 !== 1) 位址類型 += 1;
    const 位址資訊 = 解析位址資料(首區塊, 偏移量 + 3, 位址類型);
    if (!位址資訊) return null;
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移, 連接埠, 是否網域系統: 連接埠 === 53};
};
const 解析透明代理封包 = (首區塊) => {
    for (let 索引 = 0; 索引 < 56; 索引++) if (首區塊[索引] !== 雜湊位元組[索引]) return null;
    const 位址類型 = 首區塊[59];
    const 位址資訊 = 解析位址資料(首區塊, 60, 位址類型);
    if (!位址資訊) return null;
    const 連接埠 = (首區塊[位址資訊.資料偏移] << 8) | 首區塊[位址資訊.資料偏移 + 1];
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移 + 4, 連接埠, 是否網域系統: 連接埠 === 53};
};
const 解析影子代理封包 = (首區塊) => {
    const 位址類型 = 首區塊[0];
    const 位址資訊 = 解析位址資料(首區塊, 1, 位址類型);
    if (!位址資訊) return null;
    const 連接埠 = (首區塊[位址資訊.資料偏移] << 8) | 首區塊[位址資訊.資料偏移 + 1];
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移 + 2, 連接埠, 是否網域系統: 連接埠 === 53};
};
const 解析通道五封包 = (首區塊) => {
    if (首區塊[2] !== 0) return null;
    const 位址類型 = 首區塊[3];
    const 位址資訊 = 解析位址資料(首區塊, 4, 位址類型);
    if (!位址資訊) return null;
    const 連接埠 = (首區塊[位址資訊.資料偏移] << 8) | 首區塊[位址資訊.資料偏移 + 1];
    return {位址類型, 位址位元組: 位址資訊.位址位元組, 資料偏移: 位址資訊.資料偏移 + 2, 連接埠, 是否通道五: true};
};
const 解析超文本封包 = (首區塊) => {
    const 長度 = 首區塊.length;
    if (長度 < 24 || 首區塊[長度 - 4] !== 13 || 首區塊[長度 - 3] !== 10 || 首區塊[長度 - 2] !== 13 || 首區塊[長度 - 1] !== 10) return null;
    const 第二空白位置 = 首區塊.indexOf(32, 13);
    if (第二空白位置 === -1) return null;
    if (超文本授權值) {
        let 暫指標 = 首區塊.indexOf(66, 第二空白位置 + 30), 是否匹配 = false;
        while (暫指標 !== -1 && 暫指標 <= 長度 - 超文本授權值.length - 10) {
            if (首區塊[暫指標 + 1] === 97 && 首區塊[暫指標 + 2] === 115 && 首區塊[暫指標 + 3] === 105 && 首區塊[暫指標 + 4] === 99 && 首區塊[暫指標 + 5] === 32) {
                是否匹配 = true;
                for (let 次索引 = 0; 次索引 < 超文本授權值.length; 次索引++) if (首區塊[暫指標 + 6 + 次索引] !== 超文本授權值[次索引]) {
                    是否匹配 = false;
                    break;
                }
                if (是否匹配) break;
            }
            暫指標 = 首區塊.indexOf(66, 暫指標 + 1);
        }
        if (!是否匹配) return {是否認證失敗: true};
    }
    const 最後冒號位置 = 首區塊.lastIndexOf(58, 第二空白位置 - 3);
    if (最後冒號位置 < 12) return null;
    let 連接埠 = 0;
    for (let 索引 = 最後冒號位置 + 1, 數字值; 索引 < 第二空白位置 && (數字值 = 首區塊[索引] - 48) >= 0 && 數字值 <= 9; 索引++) 連接埠 = 連接埠 * 10 + 數字值;
    return {位址類型: 3, 位址位元組: 首區塊.subarray(8, 最後冒號位置), 連接埠, 資料偏移: 長度, 是否超文本: true};
};
const 第四版位址轉六四六版位址 = (第四版位址, 六四轉換前綴) => {
    const 分段陣列 = 第四版位址.split('.');
    let 十六進位字串 = "";
    for (let 索引 = 0; 索引 < 4; 索引++) {
        let 十六進位片段 = (分段陣列[索引] | 0).toString(16);
        十六進位字串 += (十六進位片段.length === 1 ? "0" + 十六進位片段 : 十六進位片段);
        if (索引 === 1) 十六進位字串 += ":";
    }
    return `[${六四轉換前綴}${十六進位字串}]`;
};
const 加密網域選項 = {headers: {'Accept': 'application/dns-json'}}, 加密網域請求標頭 = {'content-type': 'application/dns-message'};
const 並發網域系統解析 = async (主機名稱, 記錄類型) => {
    const 網域系統結果 = await Promise.any(加密網域轉換端點列表.map(端點 =>
        fetch(`${端點}?name=${主機名稱}&type=${記錄類型}`, 加密網域選項).then(回應 => {
            if (!回應.ok) throw new Error();
            return 回應.json();
        })
    ));
    const 解析答案 = 網域系統結果.Answer || 網域系統結果.answer;
    if (!解析答案 || 解析答案.length === 0) return null;
    return 解析答案;
};
const 加密網域處理 = async (負載資料) => {
    if (負載資料.byteLength < 2) return null;
    const 網域系統查詢資料 = 負載資料.subarray(2);
    const 請求回應 = await Promise.any(加密網域端點列表.map(端點 =>
        fetch(端點, {method: 'POST', headers: 加密網域請求標頭, body: 網域系統查詢資料}).then(回應 => {
            if (!回應.ok) throw new Error();
            return 回應;
        })
    ));
    const 網域系統查詢結果 = await 請求回應.arrayBuffer();
    const 使用者資料包長度 = 網域系統查詢結果.byteLength;
    const 回應封包 = new Uint8Array(2 + 使用者資料包長度);
    回應封包[0] = (使用者資料包長度 >> 8) & 0xff, 回應封包[1] = 使用者資料包長度 & 0xff;
    回應封包.set(new Uint8Array(網域系統查詢結果), 2);
    return 回應封包;
};
const 判定位址類型 = (主機名稱) => {
    const 首字元碼 = 主機名稱.charCodeAt(0);
    return (首字元碼 - 48) >>> 0 > 9 ? (首字元碼 === 91 ? 4 : 3) : 是否為第四版位址(主機名稱) ? 1 : 3;
};
const 建立六四轉換連線 = async (位址類型, 連接埠, 六四轉換參數, 位址位元組, 全域代理, 限制數量, 是否超文本) => {
    const 六四轉換前綴 = 六四轉換參數.charCodeAt(0) === 91 ? 六四轉換參數.slice(1, -1) : 六四轉換參數;
    if (!全域代理) return 並發建立連線(`[${六四轉換前綴}6815:3598]`, 連接埠, 4, 限制數量);
    const 主機名稱 = 二進位位址轉字串(位址類型, 位址位元組);
    if (是否超文本) 位址類型 = 判定位址類型(主機名稱);
    if (位址類型 === 3) {
        const 解析答案 = await 並發網域系統解析(主機名稱, 'A');
        const 位址記錄 = 解析答案?.find(記錄項 => 記錄項.type === 1);
        return 位址記錄 ? 並發建立連線(第四版位址轉六四六版位址(位址記錄.data, 六四轉換前綴), 連接埠, 4, 限制數量) : null;
    }
    if (位址類型 === 1) return 並發建立連線(第四版位址轉六四六版位址(主機名稱, 六四轉換前綴), 連接埠, 4, 限制數量);
    return 並發建立連線(主機名稱, 連接埠, 4, 限制數量);
};
const 查詢文字記錄結果 = async (查詢字串) => {
    const 解析答案 = await 並發網域系統解析(查詢字串, 'TXT');
    if (!解析答案) return null;
    let 文字記錄資料, 索引 = 0, 長度 = 解析答案.length;
    for (; 索引 < 長度; 索引++) if (解析答案[索引].type === 16) {
        文字記錄資料 = 解析答案[索引].data;
        break;
    }
    if (!文字記錄資料) return null;
    if (文字記錄資料.charCodeAt(0) === 34 && 文字記錄資料.charCodeAt(文字記錄資料.length - 1) === 34) 文字記錄資料 = 文字記錄資料.slice(1, -1);
    const 原始片段 = 文字記錄資料.split(/,|\\010|\n/), 前綴列表 = [];
    for (索引 = 0, 長度 = 原始片段.length; 索引 < 長度; 索引++) {
        const 片段 = 原始片段[索引].trim();
        if (片段) 前綴列表.push(片段);
    }
    return 前綴列表.length ? 前綴列表 : null;
};
const 代理位址正則 = /william|fxpip/;
const 連線代理位址 = async (參數值, 限制數量) => {
    if (代理位址正則.test(參數值)) {
        let 已解析位址列表 = await 查詢文字記錄結果(參數值);
        if (!已解析位址列表 || 已解析位址列表.length === 0) return null;
        if (已解析位址列表.length > 限制數量) {
            for (let 索引 = 已解析位址列表.length - 1; 索引 > 0; 索引--) {
                const 次索引 = (Math.random() * (索引 + 1)) | 0;
                [已解析位址列表[索引], 已解析位址列表[次索引]] = [已解析位址列表[次索引], 已解析位址列表[索引]];
            }
            已解析位址列表 = 已解析位址列表.slice(0, 限制數量);
        }
        const 連線承諾列表 = 已解析位址列表.map(位址項 => {
            const [主機, 連接埠] = 解析主機連接埠(位址項, 443);
            return 建立單次連線(主機, 連接埠);
        });
        return await Promise.any(連線承諾列表);
    }
    const [主機, 連接埠] = 解析主機連接埠(參數值, 443);
    const 位址類型 = 是否為網域名稱(主機) ? 3 : 0;
    return 並發建立連線(主機, 連接埠, 位址類型, 限制數量);
};
const 策略執行器映射 = new Map([
    [0, async ({位址類型, 連接埠, 位址位元組, 是否超文本}) => {
        const 主機名稱 = 二進位位址轉字串(位址類型, 位址位元組);
        if (是否超文本 && 僅網域並發) 位址類型 = 判定位址類型(主機名稱);
        return 並發建立連線(主機名稱, 連接埠, 位址類型);
    }],
    [1, async ({位址類型, 連接埠, 位址位元組}, 參數值, 限制數量) => {
        const 通道認證資訊 = 解析認證字串(參數值);
        return 經通道代理連線(位址類型, 連接埠, 通道認證資訊, 位址位元組, 限制數量);
    }],
    [2, async ({位址類型, 連接埠, 位址位元組}, 參數值, 限制數量) => {
        const 超文本認證資訊 = 解析認證字串(參數值);
        return 經超文本代理連線(位址類型, 連接埠, 超文本認證資訊, 位址位元組, 限制數量);
    }],
    [3, async (_已解析請求, 參數值, 限制數量) => {
        return 連線代理位址(參數值, 限制數量);
    }],
    [4, async ({位址類型, 連接埠, 位址位元組, 是否超文本}, 參數值, 限制數量) => {
        const {六四轉換參數, 全域代理} = 參數值;
        return 建立六四轉換連線(位址類型, 連接埠, 六四轉換參數, 位址位元組, 全域代理, 限制數量, 是否超文本);
    }]
]);
const 參數匹配正則 = /(gs5|s5all|ghttp|gnat64|nat64all|httpall|s5|socks|http|ip|nat64)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const 建立傳輸控制連線 = async (已解析請求, 請求) => {
    let 網址字串 = 請求.url, 清理路徑 = 網址字串.slice(網址字串.indexOf('/', 10) + 1), 策略列表 = [];
    if (清理路徑.length < 6) {策略列表.push({類型: 0}, {類型: 3, 參數: 機房到代理映射.get(請求.cf?.colo) ?? 代理位址表.US}, {類型: 3, 參數: 最終代理主機})} else {
        參數匹配正則.lastIndex = 0;
        let 匹配項, 暫指標 = Object.create(null);
        while ((匹配項 = 參數匹配正則.exec(清理路徑))) 暫指標[(匹配項[1] || 匹配項[3]).toLowerCase()] = 匹配項[2] ? (匹配項[2].charCodeAt(匹配項[2].length - 1) === 61 ? 匹配項[2].slice(0, -1) : 匹配項[2]) : true;
        const 通道設定 = 暫指標.gs5 || 暫指標.s5all || 暫指標.s5 || 暫指標.socks, 超文本設定 = 暫指標.ghttp || 暫指標.httpall || 暫指標.http, 六四轉換設定 = 暫指標.gnat64 || 暫指標.nat64all || 暫指標.nat64;
        const 全域代理 = !!(暫指標.gs5 || 暫指標.s5all || 暫指標.ghttp || 暫指標.httpall || 暫指標.gnat64 || 暫指標.nat64all || 暫指標.proxyall || 暫指標.globalproxy);
        if (!全域代理) 策略列表.push({類型: 0});
        const 加入策略 = (暫值, 類型值) => {
            if (!暫值) return;
            const 分段陣列 = decodeURIComponent(暫值).split(',').filter(Boolean);
            if (分段陣列.length) 策略列表.push({類型: 類型值, 參數: 分段陣列.map(區段值 => 類型值 === 4 ? {六四轉換參數: 區段值, 全域代理} : 區段值), 並行: true});
        };
        for (let 索引 = 0; 索引 < 代理策略順序.length; 索引++) {
            const 鍵索引 = 代理策略順序[索引];
            加入策略(鍵索引 === 'socks' ? 通道設定 : 鍵索引 === 'http' ? 超文本設定 : 六四轉換設定, 鍵索引 === 'socks' ? 1 : 鍵索引 === 'http' ? 2 : 4);
        }
        if (全域代理) {if (!策略列表.length) 策略列表.push({類型: 0})} else {
            加入策略(暫指標.ip, 3);
            策略列表.push({類型: 3, 參數: 機房到代理映射.get(請求.cf?.colo) ?? 代理位址表.US}, {類型: 3, 參數: 最終代理主機});
        }
    }
    for (let 索引 = 0; 索引 < 策略列表.length; 索引++) {
        try {
            const 執行函式 = 策略執行器映射.get(策略列表[索引].類型);
            const 子並發數 = (策略列表[索引]['並行'] && Array.isArray(策略列表[索引].參數)) ? Math.max(1, Math.floor(並發數量 / 策略列表[索引].參數.length)) : undefined;
            const 連線插槽 = await (策略列表[索引]['並行'] && Array.isArray(策略列表[索引].參數) ? Promise.any(策略列表[索引].參數.map(位址項 => 執行函式(已解析請求, 位址項, 子並發數))) : 執行函式(已解析請求, 策略列表[索引].參數));
            if (連線插槽) return 連線插槽;
        } catch {}
    }
    return null;
};
const 手動資料管線 = async (可讀流, 可寫通道) => {
    const _緩衝區大小 = 緩衝區大小, _最大區塊長度 = 最大區塊長度, _啟動閾值 = 啟動閾值, _刷新時間 = 刷新時間, _安全緩衝區大小 = _緩衝區大小 - _最大區塊長度;
    let 主緩衝區 = new ArrayBuffer(_緩衝區大小), 偏移量 = 0, 刷新延遲 = 2, 計時器識別 = null, 恢復函式 = null, 正在讀取 = false, 需要刷新 = false, 累積位元組 = 0;
    const 刷新輸出 = () => {
        if (正在讀取) return 需要刷新 = true;
        偏移量 > 0 && (可寫通道.send(主緩衝區.slice(0, 偏移量)), 偏移量 = 0);
        需要刷新 = false, 計時器識別 && (clearTimeout(計時器識別), 計時器識別 = null), 恢復函式?.(), 恢復函式 = null;
    };
    const 讀取器 = 可讀流.getReader({mode: 'byob'});
    try {
        while (true) {
            正在讀取 = true;
            const {done: 是否完成, value: 讀取值} = await 讀取器.read(new Uint8Array(主緩衝區, 偏移量, _最大區塊長度));
            if (正在讀取 = false, 是否完成) break;
            主緩衝區 = 讀取值.buffer;
            const 區塊長度 = 讀取值.byteLength;
            if (區塊長度 < _最大區塊長度) {
                刷新延遲 = 2, 區塊長度 < 4096 && (累積位元組 = 0);
                偏移量 > 0 ? (偏移量 += 區塊長度, 刷新輸出()) : 可寫通道.send(讀取值.slice());
            } else {
                累積位元組 += 區塊長度;
                偏移量 += 區塊長度, 計時器識別 ||= setTimeout(刷新輸出, 刷新延遲), 需要刷新 && 刷新輸出();
                偏移量 > _安全緩衝區大小 && (累積位元組 > _啟動閾值 && (刷新延遲 = _刷新時間), await new Promise(結果值 => 恢復函式 = 結果值));
            }
        }
    } finally {正在讀取 = false, 刷新輸出(), 讀取器.releaseLock()}
};
const 處理會話流程 = async (資料區塊, 狀態, 請求, 可寫通道, 關閉連線) => {
    if (狀態.通道五狀態 === 1) {
        let 是否匹配 = 資料區塊.length === 通道五認證封包.length;
        for (let 索引 = 0; 是否匹配 && 索引 < 通道五認證封包.length; 索引++) if (資料區塊[索引] !== 通道五認證封包[索引]) 是否匹配 = false;
        if (是否匹配) {
            可寫通道.send(new Uint8Array([1, 0]));
            狀態.通道五狀態 = 2;
            return;
        }
        可寫通道.send(new Uint8Array([1, 1]));
        return 關閉連線();
    }
    let 已解析請求 = null;
    if (資料區塊[0] === 5) {
        if (!狀態.通道五狀態) {
            const 需求驗證方式 = 代理使用者名稱 ? 2 : 0;
            const 方法列表 = 資料區塊.subarray(2, 2 + 資料區塊[1]);
            if (方法列表.indexOf(需求驗證方式) === -1) {
                可寫通道.send(new Uint8Array([5, 255]));
                return 關閉連線();
            }
            可寫通道.send(new Uint8Array([5, 需求驗證方式]));
            狀態.通道五狀態 = 需求驗證方式 === 2 ? 1 : 2;
            return;
        }
        if (狀態.通道五狀態 === 2 && 資料區塊[1] === 1) 已解析請求 = 解析通道五封包(資料區塊);
    } else if (資料區塊[0] === 67 && 資料區塊[1] === 79) {
        已解析請求 = 解析超文本封包(資料區塊);
        if (已解析請求?.是否認證失敗) {
            可寫通道.send(超文本認證失敗回應);
            return 關閉連線();
        }
    } else if (資料區塊.length > 58 && 資料區塊[56] === 13 && 資料區塊[57] === 10) {
        已解析請求 = 解析透明代理封包(資料區塊);
    } else if ((已解析請求 = 解析請求封包(資料區塊))) {
        可寫通道.send(new Uint8Array([資料區塊[0], 0]));
    } else {已解析請求 = 解析影子代理封包(資料區塊)}
    if (!已解析請求) return 關閉連線();
    已解析請求.是否通道五 ? 可寫通道.send(通道五回應封包) : 已解析請求.是否超文本 && 可寫通道.send(超文本連線成功回應);
    const 負載資料 = 資料區塊.subarray(已解析請求.資料偏移);
    if (已解析請求.是否網域系統) {
        const 網域系統回應封包 = await 加密網域處理(負載資料);
        if (網域系統回應封包?.byteLength) 可寫通道.send(網域系統回應封包);
        return 關閉連線();
    } else {
        狀態.傳輸控制插槽 = await 建立傳輸控制連線(已解析請求, 請求);
        if (!狀態.傳輸控制插槽) return 關閉連線();
        const 傳輸控制寫入函式 = 狀態.傳輸控制插槽.writable.getWriter();
        if (負載資料.byteLength) await 傳輸控制寫入函式.write(負載資料);
        狀態.傳輸控制寫入器 = (暫存值) => 傳輸控制寫入函式.write(暫存值);
        手動資料管線(狀態.傳輸控制插槽.readable, 可寫通道).finally(() => 關閉連線());
    }
};
const 處理網頁套接字連線 = async (網頁套接字連線, 請求) => {
    const 協議標頭 = 請求.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const 早期資料 = 協議標頭 ? Uint8Array.fromBase64(協議標頭, {alphabet: 'base64url'}) : null;
    const 狀態 = {通道五狀態: 0, 傳輸控制寫入器: null, 傳輸控制插槽: null};
    const 關閉連線 = () => {狀態.傳輸控制插槽?.close(), !早期資料 && 網頁套接字連線.close()};
    let 處理鏈 = Promise.resolve();
    const 處理資料 = async (資料區塊) => {
        if (狀態.傳輸控制寫入器) return 狀態.傳輸控制寫入器(資料區塊);
        await 處理會話流程(早期資料 ? 資料區塊 : new Uint8Array(資料區塊), 狀態, 請求, 網頁套接字連線, 關閉連線);
    };
    if (早期資料) 處理鏈 = 處理鏈.then(() => 處理資料(早期資料).catch(關閉連線));
    網頁套接字連線.addEventListener("message", 事件 => {處理鏈 = 處理鏈.then(() => 處理資料(事件.data).catch(關閉連線))});
};
const 擴展超文本回應標頭 = {'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const 處理擴展超文本請求 = async (請求) => {
    const _最大區塊長度 = 最大區塊長度;
    const 讀取器 = 請求.body.getReader({mode: 'byob'});
    const 狀態 = {通道五狀態: 0, 傳輸控制寫入器: null, 傳輸控制插槽: null};
    let 會話緩衝區 = new ArrayBuffer(_最大區塊長度), 已使用位元組 = 0;
    return new Response(new ReadableStream({
        async start(控制器) {
            const 可寫通道 = {send: (資料區塊) => 控制器.enqueue(資料區塊)}, 關閉連線 = () => {讀取器.releaseLock(), 狀態.傳輸控制插槽?.close(), 控制器.close()};
            try {
                while (true) {
                    let 偏移量 = 0, 讀取長度 = _最大區塊長度;
                    !狀態.傳輸控制寫入器 && (偏移量 = 已使用位元組, 讀取長度 = 8192);
                    const {done: 是否完成, value: 讀取值} = await 讀取器.read(new Uint8Array(會話緩衝區, 偏移量, 讀取長度));
                    if (是否完成) break;
                    會話緩衝區 = 讀取值.buffer;
                    if (狀態.傳輸控制寫入器) {
                        狀態.傳輸控制寫入器(讀取值.slice());
                        continue;
                    }
                    if (new Uint8Array(會話緩衝區)[0] !== 5 && !狀態.通道五狀態) {
                        已使用位元組 += 讀取值.byteLength;
                        if (已使用位元組 < 32) continue;
                        await 處理會話流程(new Uint8Array(會話緩衝區, 0, 已使用位元組).slice(), 狀態, 請求, 可寫通道, 關閉連線);
                    } else {await 處理會話流程(讀取值.slice(), 狀態, 請求, 可寫通道, 關閉連線)}
                    已使用位元組 = 0;
                }
            } catch {關閉連線()} finally {關閉連線()}
        },
        cancel() {狀態.傳輸控制插槽?.close(), 讀取器.releaseLock()}
    }), {headers: 擴展超文本回應標頭});
};
export default {
    async fetch(請求) {
        if (請求.method === 'POST') return 處理擴展超文本請求(請求);
        if (請求.headers.get('Upgrade') === 'websocket') {
            const {0: 客戶端插槽, 1: 網頁套接字連線} = new WebSocketPair();
            網頁套接字連線.accept();
            處理網頁套接字連線(網頁套接字連線, 請求);
            return new Response(null, {status: 101, webSocket: 客戶端插槽});
        }
        return new Response(首頁內容, {status: 200, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};
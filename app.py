import os, sqlite3, secrets, ipaddress, shlex, base64, hashlib, time, threading, re, io
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import check_password_hash
from cryptography.fernet import Fernet
import paramiko, qrcode

APP_PORT=int(os.getenv('PORT','5000'))
DATA_DIR=os.getenv('DATA_DIR','/data'); os.makedirs(DATA_DIR,exist_ok=True)
DB_PATH=os.getenv('DB_PATH',DATA_DIR+'/panel.db')
ADMIN_USERNAME=os.getenv('ADMIN_USERNAME','admin')
ADMIN_PASSWORD=os.getenv('ADMIN_PASSWORD','admin123')
SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32)
WG_IFACE=os.getenv('WG_INTERFACE','wg0')
DEFAULT_PORT=int(os.getenv('WG_PORT','51820'))
DEFAULT_SUBNET=os.getenv('WG_SUBNET','10.66.66.0/24')
DEFAULT_DNS=os.getenv('WG_DNS','1.1.1.1')
app=Flask(__name__,template_folder=os.path.dirname(os.path.abspath(__file__)))
app.secret_key=SECRET_KEY
FERNET=Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))

def db():
    c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init_db():
    c=db()
    c.execute('''CREATE TABLE IF NOT EXISTS servers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 22,username TEXT NOT NULL,auth_type TEXT NOT NULL,
      secret TEXT NOT NULL,endpoint TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,installed INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS clients(
      id INTEGER PRIMARY KEY AUTOINCREMENT,server_id INTEGER NOT NULL,name TEXT NOT NULL,
      public_key TEXT NOT NULL,private_key TEXT NOT NULL,address TEXT NOT NULL,dns TEXT NOT NULL,
      allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',created_at TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,expires_at TEXT,UNIQUE(server_id,address),
      UNIQUE(server_id,public_key),FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE)''')
    c.commit(); c.close()
init_db()

def enc(s): return FERNET.encrypt(s.encode()).decode()
def dec(s): return FERNET.decrypt(s.encode()).decode()
def now(): return datetime.now(timezone.utc).isoformat()
def get_server(i):
    c=db(); r=c.execute('SELECT * FROM servers WHERE id=?',(i,)).fetchone(); c.close(); return r
def get_client(i):
    c=db(); r=c.execute('SELECT * FROM clients WHERE id=?',(i,)).fetchone(); c.close(); return r

def login_required(f):
    @wraps(f)
    def w(*a,**k): return f(*a,**k) if session.get('logged_in') else redirect(url_for('login'))
    return w

def ssh_connect(s):
    client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    secret=dec(s['secret'])
    kwargs=dict(hostname=s['host'],port=int(s['port']),username=s['username'],timeout=15,look_for_keys=False,allow_agent=False)
    if s['auth_type']=='key':
        pkey=paramiko.RSAKey.from_private_key(io.StringIO(secret)); kwargs['pkey']=pkey
    else: kwargs['password']=secret
    client.connect(**kwargs); return client,secret

def ssh_run(s,command,sudo=True,timeout=180):
    client,secret=ssh_connect(s)
    try:
        if sudo and s['username']!='root': command='sudo -S -p "" bash -lc '+shlex.quote(command)
        stdin,stdout,stderr=client.exec_command(command,timeout=timeout,get_pty=True)
        if sudo and s['username']!='root': stdin.write(secret+'\n'); stdin.flush()
        out=stdout.read().decode(errors='replace'); err=stderr.read().decode(errors='replace'); rc=stdout.channel.recv_exit_status()
        return rc,out,err
    finally: client.close()

def sq(v): return shlex.quote(str(v))

def install_remote(s):
    script='''set -e
if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y wireguard wireguard-tools iptables iproute2 python3; elif command -v dnf >/dev/null; then dnf install -y wireguard-tools iptables iproute python3; elif command -v yum >/dev/null; then yum install -y wireguard-tools iptables iproute python3; elif command -v apk >/dev/null; then apk add wireguard-tools iptables iproute2 python3; else echo UNSUPPORTED_PACKAGE_MANAGER; exit 20; fi
install -d -m 700 /etc/wireguard
iface=%s; port=%s; subnet=%s
uplink=$(ip route show default | awk 'NR==1{print $5}'); [ -n "$uplink" ] || uplink=eth0
[ -f /etc/wireguard/server_private.key ] || wg genkey > /etc/wireguard/server_private.key
chmod 600 /etc/wireguard/server_private.key
priv=$(cat /etc/wireguard/server_private.key); printf '%%s' "$priv" | wg pubkey > /etc/wireguard/server_public.key
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.src_valid_mark=1\n' > /etc/sysctl.d/99-wireguard-panel.conf
sysctl --system >/dev/null 2>&1 || true
python3 - "$subnet" "$port" "$uplink" "$priv" <<'PY' > /etc/wireguard/$iface.conf
import ipaddress,sys
subnet,port,uplink,priv=sys.argv[1:]
net=ipaddress.ip_network(subnet,strict=False)
print('[Interface]')
print(f'Address = {net.network_address+1}/{net.prefixlen}')
print(f'ListenPort = {port}')
print(f'PrivateKey = {priv}')
print(f'PostUp = iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -o {uplink} -j MASQUERADE')
print(f'PostDown = iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -o {uplink} -j MASQUERADE')
PY
chmod 600 /etc/wireguard/$iface.conf
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then ufw allow "$port/udp"; fi
if command -v systemctl >/dev/null; then systemctl enable wg-quick@$iface; systemctl restart wg-quick@$iface; else wg-quick down $iface 2>/dev/null || true; wg-quick up $iface; fi
wg show $iface
''' % (sq(WG_IFACE),sq(DEFAULT_PORT),sq(DEFAULT_SUBNET))
    rc,out,err=ssh_run(s,script,True,240); return rc==0,(out or err).strip()

def server_public(s):
    rc,out,err=ssh_run(s,'cat /etc/wireguard/server_public.key',True,30); return out.strip() if rc==0 else ''
def endpoint(s): return s['endpoint'] or s['host']

def next_addr(s):
    net=ipaddress.ip_network(DEFAULT_SUBNET,strict=False)
    c=db(); used={r['address'].split('/')[0] for r in c.execute('SELECT address FROM clients WHERE server_id=?',(s['id'],))}; c.close()
    for h in net.hosts():
        if str(h)==str(net.network_address+1) or str(h) in used: continue
        return str(h)
    raise RuntimeError('Subnet is full')

def apply_peer(s,pub,addr,enabled):
    cmd=('wg set %s peer %s allowed-ips %s' % (sq(WG_IFACE),sq(pub),sq(addr+'/32'))) if enabled else ('wg set %s peer %s remove' % (sq(WG_IFACE),sq(pub)))
    rc,out,err=ssh_run(s,cmd,True,30); return rc==0,(out or err).strip()

def add_peer_remote(s,name,dns,expires):
    addr=next_addr(s)
    rc,out,err=ssh_run(s,'priv=$(wg genkey); pub=$(printf "%s" "$priv" | wg pubkey); printf "%s\\n%s\\n" "$priv" "$pub"',True,30)
    if rc!=0: raise RuntimeError((out or err).strip())
    vals=[x.strip() for x in out.strip().splitlines() if x.strip()]
    if len(vals)<2: raise RuntimeError('key generation failed')
    priv,pub=vals[-2],vals[-1]
    block='[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' % (pub,addr)
    cmd="printf '%%s\\n' %s >> /etc/wireguard/%s.conf; wg set %s peer %s allowed-ips %s" % (sq(block),sq(WG_IFACE),sq(WG_IFACE),sq(pub),sq(addr+'/32'))
    rc,out,err=ssh_run(s,cmd,True,30)
    if rc!=0: raise RuntimeError((out or err).strip())
    c=db(); c.execute('INSERT INTO clients(server_id,name,public_key,private_key,address,dns,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)',(s['id'],name,pub,priv,addr,dns,now(),expires)); c.commit(); cid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.close(); return cid

def remove_peer(s,pub):
    rc,out,err=ssh_run(s,'wg set %s peer %s remove' % (sq(WG_IFACE),sq(pub)),True,30)
    if rc!=0:return False,(out or err).strip()
    script="awk -v key=%s 'BEGIN{RS=\"\"; ORS=\"\\n\\n\"} $0 !~ \"PublicKey[[:space:]]*=[[:space:]]*\" key {print}' /etc/wireguard/%s.conf > /etc/wireguard/%s.conf.tmp && mv /etc/wireguard/%s.conf.tmp /etc/wireguard/%s.conf" % (sq(pub),sq(WG_IFACE),sq(WG_IFACE),sq(WG_IFACE),sq(WG_IFACE))
    ssh_run(s,script,True,30); return True,''

def expired(v):
    if not v:return False
    try:
        d=datetime.fromisoformat(v.replace('Z','+00:00')); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc); return d<=datetime.now(timezone.utc)
    except:return True

def expiry_worker():
    while True:
        try:
            c=db(); rows=c.execute('SELECT * FROM clients WHERE enabled=1 AND expires_at IS NOT NULL').fetchall(); c.close()
            for r in rows:
                if expired(r['expires_at']):
                    s=get_server(r['server_id'])
                    if s: apply_peer(s,r['public_key'],r['address'],False)
                    c=db(); c.execute('UPDATE clients SET enabled=0 WHERE id=?',(r['id'],)); c.commit(); c.close()
        except Exception: pass
        time.sleep(30)
threading.Thread(target=expiry_worker,daemon=True).start()

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form.get('username',''); p=request.form.get('password','')
        ok=u==ADMIN_USERNAME and (check_password_hash(ADMIN_PASSWORD,p) if ADMIN_PASSWORD.startswith(('pbkdf2:','scrypt:')) else secrets.compare_digest(p,ADMIN_PASSWORD))
        if ok: session['logged_in']=True; return redirect(url_for('dashboard'))
        flash('نام کاربری یا رمز اشتباه است')
    return render_template('login.html')
@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    c=db(); servers=c.execute('SELECT * FROM servers ORDER BY id DESC').fetchall(); clients=c.execute('SELECT * FROM clients ORDER BY id DESC').fetchall(); c.close(); return render_template('dashboard.html',servers=servers,clients=clients)

@app.route('/servers/add',methods=['POST'])
@login_required
def add_server():
    try:
        name=request.form.get('name','').strip() or 'VPS'; host=request.form.get('host','').strip(); port=int(request.form.get('port') or 22); user=request.form.get('username','root').strip(); auth=request.form.get('auth_type','password'); secret=request.form.get('secret',''); ep=request.form.get('endpoint','').strip()
        if not host or not secret: raise ValueError('IP/Host and SSH credential are required')
        if auth=='password': ipaddress.ip_address(host) if host.replace('.','').isdigit() else None
        c=db(); c.execute('INSERT INTO servers(name,host,port,username,auth_type,secret,endpoint,created_at) VALUES(?,?,?,?,?,?,?,?)',(name,host,port,user,auth,enc(secret),ep,now())); c.commit(); c.close(); flash('سرور اضافه شد؛ حالا Install WireGuard را بزنید.')
    except Exception as e: flash('خطا: '+str(e))
    return redirect(url_for('dashboard'))

@app.route('/servers/<int:sid>/install',methods=['POST'])
@login_required
def install(sid):
    s=get_server(sid)
    if not s:return 'not found',404
    try:
        ok,msg=install_remote(s); c=db(); c.execute('UPDATE servers SET installed=? WHERE id=?',(1 if ok else 0,sid)); c.commit(); c.close(); flash(('نصب واقعی موفق شد: ' if ok else 'نصب ناموفق: ')+msg[:700])
    except Exception as e: flash('نصب ناموفق: '+str(e))
    return redirect(url_for('dashboard'))

@app.route('/servers/<int:sid>/status')
@login_required
def status(sid):
    s=get_server(sid)
    if not s:return 'not found',404
    rc,out,err=ssh_run(s,'wg show '+sq(WG_IFACE)+' || true',True,30); return jsonify(ok=rc==0,text=out or err)

@app.route('/clients/add',methods=['POST'])
@login_required
def add_client():
    try:
        sid=int(request.form['server_id']); s=get_server(sid)
        if not s: raise ValueError('server not found')
        name=request.form.get('name','').strip() or 'client'; dns=request.form.get('dns','').strip() or DEFAULT_DNS; ex=request.form.get('expires_at','').strip(); expires=None
        if ex:
            dt=datetime.fromisoformat(ex); dt=dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc); expires=dt.astimezone(timezone.utc).isoformat()
            if expired(expires): raise ValueError('تاریخ انقضا باید آینده باشد')
        cid=add_peer_remote(s,name,dns,expires); flash('کلاینت واقعی ساخته شد.'); return redirect(url_for('conf',cid=cid))
    except Exception as e: flash('ساخت کلاینت ناموفق: '+str(e)); return redirect(url_for('dashboard'))

def client_conf(r):
    s=get_server(r['server_id']); pub=server_public(s); prefix=ipaddress.ip_network(DEFAULT_SUBNET,strict=False).prefixlen
    return '[Interface]\nPrivateKey = %s\nAddress = %s/%s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s\nPersistentKeepalive = 25\n' % (r['private_key'],r['address'],prefix,r['dns'],pub,endpoint(s),DEFAULT_PORT,r['allowed_ips'])

@app.route('/clients/<int:cid>/conf')
@login_required
def conf(cid):
    r=get_client(cid)
    if not r:return 'not found',404
    name=re.sub(r'[^A-Za-z0-9_.-]','_',r['name'])+'.conf'; return send_file(io.BytesIO(client_conf(r).encode()),as_attachment=True,download_name=name,mimetype='text/plain')
@app.route('/clients/<int:cid>/qr.png')
@login_required
def qr(cid):
    r=get_client(cid)
    if not r:return 'not found',404
    b=io.BytesIO(); qrcode.make(client_conf(r)).save(b,'PNG'); b.seek(0); return send_file(b,mimetype='image/png',download_name='wireguard-qr.png')
@app.route('/clients/<int:cid>/toggle',methods=['POST'])
@login_required
def toggle(cid):
    r=get_client(cid); s=get_server(r['server_id']) if r else None
    if not r:return 'not found',404
    if not r['enabled'] and expired(r['expires_at']): flash('کلاینت منقضی شده؛ ابتدا تمدید کنید.'); return redirect(url_for('dashboard'))
    ok,msg=apply_peer(s,r['public_key'],r['address'],not bool(r['enabled']))
    if ok:
        c=db(); c.execute('UPDATE clients SET enabled=? WHERE id=?',(0 if r['enabled'] else 1,cid)); c.commit(); c.close()
    flash('وضعیت تغییر کرد.' if ok else 'خطا: '+msg); return redirect(url_for('dashboard'))
@app.route('/clients/<int:cid>/delete',methods=['POST'])
@login_required
def delete(cid):
    r=get_client(cid); s=get_server(r['server_id']) if r else None
    if not r:return 'not found',404
    remove_peer(s,r['public_key']); c=db(); c.execute('DELETE FROM clients WHERE id=?',(cid,)); c.commit(); c.close(); flash('کلاینت حذف شد.'); return redirect(url_for('dashboard'))
@app.route('/clients/<int:cid>/renew',methods=['POST'])
@login_required
def renew(cid):
    r=get_client(cid); s=get_server(r['server_id']) if r else None
    try:
        ex=request.form['expires_at']; dt=datetime.fromisoformat(ex); dt=dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc); ex=dt.astimezone(timezone.utc).isoformat()
        if expired(ex): raise ValueError
        ok,msg=apply_peer(s,r['public_key'],r['address'],True)
        if not ok: raise RuntimeError(msg)
        c=db(); c.execute('UPDATE clients SET expires_at=?,enabled=1 WHERE id=?',(ex,cid)); c.commit(); c.close(); flash('تمدید شد.')
    except Exception as e: flash('تمدید ناموفق: '+str(e))
    return redirect(url_for('dashboard'))
@app.route('/api/health')
def health(): return jsonify(ok=True,time=now())
if __name__=='__main__': app.run(host='0.0.0.0',port=APP_PORT)

# server-audit.py
#!/usr/bin/env python3
"""Read-only, bounded Linux audit. Python 3.6+. No shell, installs or scans."""
import argparse, datetime as dt, glob, json, os, re, shutil, stat, subprocess, sys, time
CAP=262144
START=time.monotonic()
DEADLINE=120
ERRORS=[]
def read(path, tail=False):
    try:
        with open(path,'rb') as f:
            if tail: f.seek(max(0,os.fstat(f.fileno()).st_size-CAP))
            return f.read(CAP).decode('utf-8','replace')
    except OSError: return ''
def run(*args):
    if time.monotonic()-START>DEADLINE: return ''
    if not shutil.which(args[0]) and not os.path.isfile(args[0]): return ''
    try:
        # pipe drained in bounded chunks; kill runaway output/process group at deadline
        import selectors, signal
        p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
        sel=selectors.DefaultSelector(); sel.register(p.stdout,selectors.EVENT_READ)
        out=bytearray(); end=time.monotonic()+min(8,max(0.1,DEADLINE-(time.monotonic()-START)))
        while time.monotonic()<end and len(out)<1048576:
            events=sel.select(min(.2,max(0,end-time.monotonic())))
            if events:
                b=os.read(p.stdout.fileno(),min(65536,1048576-len(out)))
                if not b:
                    try: p.wait(timeout=.2)
                    except subprocess.TimeoutExpired: pass
                    break
                out.extend(b)
            elif p.poll() is not None: break
        if p.poll() is None: os.killpg(p.pid,signal.SIGKILL)
        p.wait(); sel.close(); p.stdout.close()
        if p.returncode not in (0,100): return ''
        return out.decode('utf-8','replace')
    except (OSError,ValueError): return ''
def jrun(*args):
    try: return json.loads(run(*args))
    except ValueError: return {}
def objects(data,key):
    if not isinstance(data,dict): return []
    value=data.get('data',{}).get(key,[]) if isinstance(data.get('data'),dict) else []
    if isinstance(value,dict): value=list(value.values())
    return [x for x in value if isinstance(x,dict)] if isinstance(value,list) else []
def enabled(v): return str(v).lower() in ('1','yes','true','on','enabled')
def cfg(path):
    return dict((m.group(1).lower(),m.group(2).strip().strip('\"\'')) for m in re.finditer(r'^\s*([\w]+)\s*[:=]\s*(.*?)\s*$',read(path),re.M))
def stamp(v):
    try:
        if isinstance(v,(int,float)) or str(v).isdigit(): return float(v)
        return dt.datetime.fromisoformat(str(v).replace('Z','+00:00')).timestamp()
    except (ValueError,AttributeError):
        try: return dt.datetime.strptime(str(v)[:19],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError: return 0
SECTIONS={}
def put(section,label,status,details):
    SECTIONS.setdefault(section,{})[label]=status+' - '+str(details).replace('\n','; ')[:2200]
def unknown(s,l,d='No reliable evidence; manual verification required'): put(s,l,'Unknown',d)
def latest_files(roots,pattern,limit=12):
    # bounded traversal: at most 5000 entries, four levels, no symlinks followed
    found=[]; count=0
    for root in roots:
        if not os.path.isdir(root): continue
        for base,dirs,files in os.walk(root,followlinks=False):
            dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(base,d))]
            if base[len(root):].count(os.sep)>=3: dirs[:]=[]
            count+=len(dirs)+len(files)
            for name in files:
                p=os.path.join(base,name)
                if re.search(pattern,name,re.I) and not os.path.islink(p):
                    try: found.append((os.stat(p).st_mtime,p))
                    except OSError: pass
            if count>=5000: break
        if count>=5000: break
    return sorted(found,reverse=True)[:limit]
def report_check(kind,days):
    pattern=r'(cms|outdated).*\.(txt|log|json)$' if kind=='cms' else r'(malware|scan).*(report|result|detail).*\.(txt|log|json)$'
    candidates=latest_files(['/root/scripts'],pattern)
    if kind!='cms': candidates=[x for x in candidates if not re.search('cms|outdated',x[1],re.I)]
    if not candidates: return 'Unknown','No matching report in /root/scripts'
    modified,path=candidates[0]; text=read(path,True)
    age=(time.time()-modified)/86400
    evidence='{}; mtime={} UTC; age={:.1f}d (mtime is not proof of scan completion)'.format(path,dt.datetime.utcfromtimestamp(modified).isoformat(),age)
    if age>days: return 'Warning','Stale report; '+evidence
    if not text.strip(): return 'Unknown','Empty report; '+evidence
    if kind=='cms':
        bad=re.search(r'(?im)^.*(?:WordPress|Joomla|Drupal|Magento|PHPMailer|CMS).*(?:outdated|unsupported|end.of.life|\bEOL\b)|^\s*(?:outdated|unsupported)\s*(?:CMS|packages?)\s*:\s*[1-9]',text)
        good=re.search(r'(?i)(?:no outdated (?:CMS|packages?|software)|outdated (?:CMS|packages?)\s*:\s*0\b|all (?:CMS|packages?) (?:are )?(?:up.to.date|supported))',text)
    else:
        bad=re.search(r'(?im)^\s*File:\s*/|infected files\s*:\s*[1-9]\d*|^.*\bFOUND\s*$|malware (?:found|detected)\s*:\s*[1-9]',text)
        good=re.search(r'(?i)(?:infected files\s*:\s*0\b|no malware (?:found|detected)|scan (?:completed|finished).*clean)',text)
    if bad: return 'Warning','Findings present; '+evidence+'; '+bad.group(0)[:160]
    if good: return 'Good','Explicit clean/current summary; '+evidence
    return 'Unknown','Report format has no explicit verdict; '+evidence

def jetbackup(days):
    binary=shutil.which('jetbackup5api')
    if not binary:
        for p in ['/usr/bin/jetbackup5api','/usr/local/jetapps/usr/bin/jetbackup5api']:
            if os.path.isfile(p): binary=p; break
    if not binary: return False
    jobs=objects(jrun(binary,'-F','listBackupJobs','-O','json'),'jobs')
    destinations=objects(jrun(binary,'-F','listDestinations','-O','json'),'destinations')
    schedules=objects(jrun(binary,'-F','listSchedules','-O','json'),'schedules')
    smap={s.get('_id'):s for s in schedules}
    dmap={d.get('_id'):d for d in destinations}
    active=[j for j in jobs if not enabled(j.get('disabled'))]
    if not jobs:
        for label in ['Local Backup','Remote Backup','Daily Backup','Weekly Backup','Monthly Backup','Recent Last Backup']:
            unknown('4. Backup',label,'JetBackup detected but API unreadable/empty; native backups checked separately in evidence')
        return True
    frequencies={2:[],3:[],4:[]}; local=[]; remote=[]; statuses=[]; jobnotes=[]
    for job in active[:20]:
        name=str(job.get('name',job.get('_id','job')))[:100]
        for sched in job.get('schedules',[]) or []:
            s=sched if isinstance(sched,dict) else smap.get(sched,{})
            try: t=int(s.get('type',0))
            except (ValueError,TypeError): t=0
            if t in frequencies and not enabled(s.get('disabled')): frequencies[t].append(name+'; days='+str(s.get('type_data','unspecified')))
        for dest in job.get('destination_details',[]) or [dmap.get(i,{}) for i in job.get('destination',[]) or []]:
            if not isinstance(dest,dict) or enabled(dest.get('disabled')): continue
            dtype=str(dest.get('type',''))
            if not dtype: continue
            (local if dtype.lower().startswith('local') else remote).append(name+' -> '+str(dest.get('name','destination'))+' ('+dtype+')')
        jid=str(job.get('_id',''))
        if not re.fullmatch(r'[a-zA-Z0-9_-]+',jid): continue
        logs=objects(jrun(binary,'-F','listLogs','-D','find[type]=1&find[info.ID]='+jid+'&sort[start_time]=-1&limit=10','-O','json'),'logs')
        logs=[l for l in logs if str(l.get('type'))=='1']
        latest=max(logs,key=lambda l:stamp(l.get('start_time')),default={})
        code=str(latest.get('status',''))
        ended=stamp(latest.get('end_time')); age=(time.time()-ended)/86400 if ended else None
        state='Good' if code=='1' and age is not None and 0<=age<=days else 'Warning' if code in ('2','3','4','5') or (age is not None and age>days) else 'Unknown'
        statuses.append(state)
        statusnames={'1':'Completed','2':'Failed','3':'Aborted','4':'Partially Complete','5':'Never Finished','6':'Processing'}
        note=name+': '+statusnames.get(code,'Unknown')+'; ended='+str(latest.get('end_time','unknown'))+'; log='+str(latest.get('file','unknown'))
        logpath=latest.get('file','')
        if isinstance(logpath,str) and logpath.startswith('/usr/local/jetapps/var/log/jetbackup5/'):
            tail=read(logpath,True)
            failures=[line[:150] for line in tail.splitlines() if re.search(r'\b(error|failed|aborted|partial)\b',line,re.I)]
            if failures:
                note+='; log findings: '+' | '.join(failures[-3:]); statuses[-1]='Warning'
        jobnotes.append(note)
    if len(active)>20:
        statuses.append('Unknown'); jobnotes.append('Only first 20 enabled jobs inspected; overall coverage incomplete')
    for label,vals in [('Local Backup',local),('Remote Backup',remote)]:
        put('4. Backup',label,'Good' if vals else 'Unknown','JetBackup enabled job destinations: '+' | '.join(vals) if vals else 'No matching enabled destination proven; not a restore/integrity test')
    for t,label in [(2,'Daily Backup'),(3,'Weekly Backup'),(4,'Monthly Backup')]:
        put('4. Backup',label,'Good' if frequencies[t] else 'Unknown','JetBackup configured '+label+': '+' | '.join(frequencies[t]) if frequencies[t] else 'No '+label+' schedule established from API; may be unreturned/paginated')
    put('4. Backup','Recent Last Backup','Warning' if 'Warning' in statuses else 'Unknown' if not statuses or 'Unknown' in statuses else 'Good',' | '.join(jobnotes) or 'No enabled job results; maximum 20 jobs inspected')
    unknown('4. Backup','Size Of Last Backup','No authoritative per-run size returned; no expensive backup-directory traversal')
    return True

def native_backup(panel):
    s='4. Backup'
    if panel=='cpanel':
        c=cfg('/var/cpanel/backups/config'); master=enabled(c.get('backupenable'))
        put(s,'Local Backup','Good' if master and enabled(c.get('keeplocal')) else 'Warning' if c else 'Unknown','Native cPanel configuration; enabled='+str(master)+'; KEEPLOCAL='+c.get('keeplocal','unknown')+'; storage='+c.get('backupdir','unknown'))
        for label,key in [('Daily Backup','backup_daily_enable'),('Weekly Backup','backup_weekly_enable'),('Monthly Backup','backup_monthly_enable')]:
            put(s,label,'Good' if master and enabled(c.get(key)) else 'Warning' if c else 'Unknown','Native cPanel master='+str(master)+'; '+key+'='+c.get(key,'unknown'))
        dests=jrun('whmapi1','--output=json','backup_destination_list')
        vals=dests.get('data',{}).get('destinations',[]) if isinstance(dests,dict) else []
        if isinstance(vals,dict): vals=list(vals.values())
        names=[str(d.get('name','destination')) for d in vals if isinstance(d,dict) and not enabled(d.get('disabled')) and enabled(d.get('enabled',True))]
        put(s,'Remote Backup','Good' if names and master else 'Unknown','Native cPanel destinations: '+(', '.join(names) or 'not established')+'; configuration is not success proof')
    if panel=='plesk':
        # Read-only SELECT: whitelist output fields; never print backup credentials.
        db=run('plesk','db','-Ne',"SELECT active,period,last FROM BackupsScheduled LIMIT 100")
        schedule_notes=[]
        for line in db.splitlines():
            fields=line.split('\t')
            if len(fields)==3: schedule_notes.append('active='+fields[0]+'; period='+fields[1]+'; last='+fields[2])
        for label,period in [('Daily Backup','daily'),('Weekly Backup','weekly'),('Monthly Backup','monthly')]:
            found=[x for x in schedule_notes if 'active=true' in x.lower() or 'active=1;' in x]
            found=[x for x in found if ('period='+period) in x.lower()]
            put(s,label,'Good' if found else 'Unknown','Plesk scheduled backup SELECT: '+' | '.join(found) if found else 'Plesk schedule schema/period not established; no disabled verdict inferred')
    if panel=='directadmin':
        configs=latest_files(['/usr/local/directadmin/data/admin'],r'backup.*(?:conf|list)$|admin\.backup',6)
        evidence=[]
        for m,p in configs:
            c=cfg(p)
            evidence.append(p+'; '+', '.join(k+'='+str(v)[:60] for k,v in c.items() if k in ['cron','cronminute','cronhour','crondayofmonth','cronmonth','crondayofweek','local_path','ftp','enabled']))
        for label in ['Local Backup','Remote Backup','Daily Backup','Weekly Backup','Monthly Backup']:
            unknown(s,label,'DirectAdmin configuration candidates: '+' | '.join(evidence) if evidence else 'DirectAdmin backup schedule not proven from standard admin files')
    roots={'cpanel':['/usr/local/cpanel/logs/cpbackup','/usr/local/cpanel/logs/cpbackup_transporter'],'plesk':['/var/log/plesk/PMM','/usr/local/psa/PMM/logs'],'directadmin':['/var/log/directadmin'],'none':['/var/log/backup','/var/log/restic','/var/log/borg']}[panel]
    files=latest_files(roots,r'backup|\.log$',6)
    if files:
        m,p=files[0]; tail=read(p,True)
        failed=re.search(r'(?i)\b(failed|aborted|partially complete)\b|\berror\s*:',tail)
        complete=re.search(r'(?i)(?:backup|transport|task).*(?:completed successfully|finished successfully)|Backup process completed',tail)
        state='Warning' if failed else 'Unknown' # uncorrelated free-text success must not prove all jobs/destinations
        put(s,'Recent Last Backup',state,'Latest candidate log '+p+'; mtime='+dt.datetime.utcfromtimestamp(m).isoformat()+' UTC; '+('failure marker present' if failed else 'completion marker present; overall job/destination success unverified' if complete else 'no terminal success verdict'))
    else: unknown(s,'Recent Last Backup','No backup log found at standard '+panel+' paths')
    cron=run('crontab','-l')+'\n'+read('/etc/crontab')
    for p in glob.glob('/etc/cron.d/*')[:100]: cron+='\n'+read(p)
    lines=[l for l in cron.splitlines() if not l.lstrip().startswith('#') and re.search(r'backup|borg|restic|duplicity|rclone',l,re.I)]
    for label in ['Daily Backup','Weekly Backup','Monthly Backup']:
        if label not in SECTIONS.get(s,{}): unknown(s,label,'Backup cron candidates='+str(len(lines))+'; cadence requires known job configuration (cron alone does not prove success)')
    for label in ['Local Backup','Remote Backup','Size Of Last Backup']:
        if label not in SECTIONS.get(s,{}): unknown(s,label,'Native '+panel+' destination/size not authoritatively available; JetBackup checked independently')

def main():
    global DEADLINE
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--panel',choices=['auto','cpanel','plesk','directadmin','none'],default='auto')
    ap.add_argument('--choose',action='store_true'); ap.add_argument('--format',choices=['text','json'],default='text')
    ap.add_argument('--max-seconds',type=int,default=120); ap.add_argument('--report-max-age-days',type=int,default=14)
    ap.add_argument('--backup-max-age-days',type=int,default=8)
    a=ap.parse_args(); DEADLINE=max(10,min(a.max_seconds,600))
    panel=a.panel
    if a.choose:
        print('1 cPanel / 2 Plesk / 3 Non-panel / 4 DirectAdmin / 0 Auto',file=sys.stderr)
        print('Panel: ',end='',file=sys.stderr,flush=True)
        panel={'1':'cpanel','2':'plesk','3':'none','4':'directadmin','0':'auto'}.get(input().strip(),'auto')
    if panel=='auto': panel='cpanel' if os.path.isfile('/usr/local/cpanel/version') else 'plesk' if os.path.isfile('/usr/local/psa/version') else 'directadmin' if os.path.isfile('/usr/local/directadmin/directadmin') else 'none'
    oscfg=cfg('/etc/os-release'); osid=oscfg.get('id','unknown'); version=oscfg.get('version_id','unknown')
    raw=read('/usr/local/cpanel/version').strip().splitlines()[0] if read('/usr/local/cpanel/version').strip() else ''
    v=re.fullmatch(r'(?:11\.)?(\d+)\.(\d+)\.(\d+)',raw)
    display='cPanel {}.{} (build {}) [raw: {}]'.format(*v.groups(),raw) if panel=='cpanel' and v else run('plesk','version').strip() if panel=='plesk' else run('/usr/local/directadmin/directadmin','v').strip() if panel=='directadmin' else 'None' if panel=='none' else raw
    system={'Hostname':run('hostname','-f').strip() or run('hostname').strip(),'OS / Version':osid+' '+version,'Control Panel':display,'Panel Type':panel,'Kernel':run('uname','-r').strip(),'Generated':dt.datetime.now(dt.timezone.utc).isoformat()}
    units=run('systemctl','list-units','--type=service','--state=running','--no-legend','--no-pager')
    active=lambda name: bool(re.search(r'(?m)^\s*'+re.escape(name)+r'\.service\s',units))
    imunify=active('imunify360') or active('imunify360-agent') or active('imunify360-firewall')
    if not imunify and shutil.which('imunify360-agent'):
        imunify=run('systemctl','is-active','imunify360').strip()=='active'
    put('1. Threat Protection','Web App Firewall','Good' if imunify else 'Unknown','Imunify360 active (requested audit policy); per-domain WAF exclusions/detection-only mode still require review' if imunify else 'No running Imunify360 service proven; ModSecurity rule activation requires manual confirmation')
    fw=[n for n in ['firewalld','csf','lfd','nftables','imunify360','imunify360-firewall'] if active(n)]
    put('1. Threat Protection','System Firewall','Good' if fw or imunify else 'Unknown','Active services: '+(', '.join(fw) or 'none proven')+'; service state alone does not test filtering rules')
    put('1. Threat Protection','Failed Login Detection','Good' if imunify or active('lfd') or active('fail2ban') else 'Unknown','Imunify360/lfd/fail2ban active' if imunify or active('lfd') or active('fail2ban') else 'No active detector proven')
    scanner=imunify or active('clamd') or active('clamd@scan')
    put('1. Threat Protection','Malware Scanner','Good' if scanner else 'Unknown','Active scanner service' if scanner else 'No running scanner proven; report checks are separate')
    unknown('1. Threat Protection','Rootkit Scanner','Installed: '+', '.join(x for x in ['rkhunter','chkrootkit'] if shutil.which(x))+'; existing scan results checked separately')
    # Cached package metadata only: no refresh, installs or downloads.
    packages=run('rpm','-qa','--qf','%{NAME} %{VERSION}\n') if shutil.which('rpm') else run('dpkg-query','-W','-f=${Package} ${Version}\n')
    updates=run('dnf','-C','check-update','--quiet') if shutil.which('dnf') else run('yum','-C','check-update','--quiet') if shutil.which('yum') else run('apt','list','--upgradable')
    for label in ['Operating System','PHP','Web Server','Database Server','Other Softwares']:
        unknown('2. Software Updates',label,'Cached metadata only; '+str(len(updates.splitlines()))+' output lines; cache freshness cannot prove current patch status')
    tiers=read('/var/cpanel/cpanel.version.tiers'); tier=cfg('/etc/cpupdate.conf').get('cpanel','release')
    target=re.search(r'(?m)^'+re.escape(tier)+r':\s*([\d.]+)',tiers)
    if panel=='cpanel' and v and target:
        installed=tuple(map(int,v.groups())); tv=target.group(1).removeprefix('11.') if hasattr(str,'removeprefix') else re.sub(r'^11\.','',target.group(1))
        put('2. Software Updates','Control Panel','Warning' if installed<tuple(map(int,tv.split('.'))) else 'Unknown','Installed '+display+'; cached tier '+tier+'='+target.group(1)+'; freshness unverified')
    else: unknown('2. Software Updates','Control Panel','Installed '+display+'; latest vendor version not fetched in read-only offline mode')
    cms=report_check('cms',a.report_max_age_days)
    put('2. Software Updates','CMS',*cms)
    # OS lifecycle catalogue is deliberately narrow and date-stamped.
    today=dt.date.today(); major=version.split('.')[0]
    ends={('centos','7'):'2024-06-30',('cloudlinux','7'):'2024-06-30',('almalinux','8'):'2029-03-01',('almalinux','9'):'2032-05-31',('rocky','8'):'2029-05-31',('rocky','9'):'2032-05-31',('ubuntu','20'):'2025-05-31',('ubuntu','22'):'2027-05-31',('ubuntu','24'):'2029-05-31',('debian','11'):'2026-08-31',('debian','12'):'2028-06-30'}
    end=ends.get((osid,major))
    if end: put('5. Software Life Time','Operating System','Warning' if today>=dt.datetime.strptime(end,'%Y-%m-%d').date() else 'Good',osid+' '+version+'; standard/LTS support ends '+end+'; extended paid coverage not independently verified; policy snapshot 2026-10-02')
    else: unknown('5. Software Life Time','Operating System',osid+' '+version+'; not in bounded lifecycle catalogue')
    if panel=='cpanel' and v and v.group(1)=='110':
        put('5. Software Life Time','Control Panel','Warning','cPanel 110: ELS exception through 2027-01-01 on eligible CentOS/CloudLinux 7; limited support, plan migration; installed '+display if today<dt.date(2027,1,1) else 'cPanel 110 ELS ended 2027-01-01; '+display)
    else: unknown('5. Software Life Time','Control Panel',display+'; vendor branch lifecycle not proven')
    put('5. Software Life Time','CMS',*cms)
    phpversions=sorted(set(re.findall(r'(?:ea|alt|plesk)-php(\d{2})(?:\D|$)',packages)))
    phpol=[x for x in phpversions if int(x)<=81 or (x=='82' and today>=dt.date(2027,1,1))]
    stack=[l for l in packages.splitlines() if re.match(r'(php|ea-php|alt-php|plesk-php|httpd|apache|nginx|mariadb|mysql|openssl)(?:\s|[-0-9])',l,re.I)][:45]
    put('5. Software Life Time','Software Stack','Warning' if phpol else 'Unknown','Upstream EOL PHP families: '+(', '.join(phpol) or 'not proven')+'; distro/CloudLinux backports may extend coverage and require entitlement verification; inventory: '+' | '.join(stack))
    native_backup(panel); jetbackup(a.backup_max_age_days)
    mount=run('findmnt','-T','/tmp','-n','-o','TARGET,OPTIONS').strip()
    opts=set(mount.split()[-1].split(',')) if mount else set()
    try: tmpstat=os.stat('/tmp'); mode=stat.S_IMODE(tmpstat.st_mode); perm=mode==0o1777 and tmpstat.st_uid==0
    except OSError: perm=False; mode=0
    secure=perm and {'noexec','nosuid','nodev'}<=opts
    put('6. Proactive Defence','/tmp Security','Good' if secure else 'Warning' if mount else 'Unknown','Effective mount='+mount+'; mode='+oct(mode)+'; root-owned 1777='+str(perm)+'; requires noexec,nosuid,nodev; these flags are hardening, not a malware guarantee')
    put('6. Proactive Defence','Malware Scan',*report_check('malware',a.report_max_age_days))
    rootkit=read('/var/log/rkhunter.log',True)
    put('6. Proactive Defence','Rootkit Check','Warning' if re.search(r'(?i)warning',rootkit) else 'Unknown','/var/log/rkhunter.log warning markers present; review' if re.search(r'(?i)warning',rootkit) else 'No explicit fresh clean rootkit completion established')
    ssh=run('sshd','-T') or run('/usr/sbin/sshd','-T')
    sc=dict(l.split(None,1) for l in ssh.splitlines() if len(l.split(None,1))==2)
    root=sc.get('permitrootlogin','unknown'); auth=sc.get('passwordauthentication','unknown')
    put('6. Proactive Defence','SSH Root Access Security','Good' if root in ['no','prohibit-password','without-password'] and auth=='no' else 'Warning' if sc else 'Unknown','Effective global permitrootlogin='+root+'; passwordauthentication='+auth+'; Match blocks/client contexts require separate review')
    unknown('6. Proactive Defence','Reboot Procedure','Provider console/recovery procedure is not discoverable safely')
    unknown('6. Proactive Defence','IP RDNS','No external DNS lookup in offline mode')
    unknown('6. Proactive Defence','PHP Functions Security','Per-pool/per-domain PHP configuration is not safely inferred from one global file')
    shadow=read('/etc/shadow'); line=next((l for l in shadow.splitlines() if l.startswith('root:')),'').split(':')
    age=int(time.time()/86400)-int(line[2]) if len(line)>2 and line[2].isdigit() else None
    put('6. Proactive Defence','Root password health','Warning' if age is not None and age>180 else 'Unknown','Password age='+str(age)+' days; locked/key-only accounts need policy review (no password hash output)')
    put('3. Server Health','Server Uptime','Good',read('/proc/uptime').split(' ')[0]+' seconds')
    load=os.getloadavg()[0]; cpus=os.cpu_count() or 1
    put('3. Server Health','CPU Usage','Warning' if load/cpus>1 else 'Good','1m load='+str(load)+'; CPU count='+str(cpus)+'; normalized='+str(round(load/cpus,2))+' (load includes I/O wait)')
    mem=dict((k,int(v)) for k,v in re.findall(r'^(\w+):\s*(\d+)',read('/proc/meminfo'),re.M))
    used=100*(1-mem.get('MemAvailable',0)/max(mem.get('MemTotal',1),1))
    put('3. Server Health','RAM Usage','Warning' if used>90 else 'Good','MemAvailable-based usage {:.1f}%'.format(used))
    disks=run('df','-P','-l').splitlines()[1:]; high=[l for l in disks if re.search(r'\b(?:9\d|100)%',l)]
    put('3. Server Health','Disc Space Usage','Warning' if high else 'Good' if disks else 'Unknown',' | '.join(high or disks)[:1800])
    web=[n for n in ['httpd','apache2','nginx','lshttpd','lsws'] if active(n)]
    put('3. Server Health','HTTP Uptime','Good' if web else 'Unknown','Running: '+','.join(web)+'; service state is not an HTTP availability test')
    queue=run('exim','-bpc').strip()
    put('3. Server Health','Email Queue','Warning' if queue.isdigit() and int(queue)>100 else 'Good' if queue.isdigit() else 'Unknown','Exim queue='+queue if queue else 'No authoritative queue result')
    unknown('3. Server Health','IP Reputation','DNSBL checks omitted in offline mode')
    if a.format=='json': print(json.dumps({'schema':'linux-audit-v6','system':system,'sections':SECTIONS},indent=2))
    else:
        print('DETAILED TECHNICAL LOG\n======================\nGenerated: '+system['Generated']+'\n\n=== System Information ===')
        for k,vv in system.items():
            if k!='Generated': print('{:22}: {}'.format(k,vv))
        for section in sorted(SECTIONS):
            print('\n=== '+section+' ===')
            for k,vv in SECTIONS[section].items(): print('{:24}: {}'.format(k,vv))
        print('\nAudit Complete! Read-only; elapsed {:.1f}s; unavailable/ambiguous evidence remains Unknown.'.format(time.monotonic()-START))
if __name__=='__main__': main()

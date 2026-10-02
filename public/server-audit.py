#!/usr/bin/env python3
"""Read-only, bounded Linux audit. Python 3.6+. No shell, installs or scans."""
import sys
sys.dont_write_bytecode=True
import argparse, datetime as dt, glob, json, os, re, shutil, stat, subprocess, sys, time
CAP=262144
START=time.monotonic()
DEADLINE=120
ERRORS=[]
RUN_META={}
RUN_OUTPUT={}
NET_CACHE={}
ONLINE=True
def read(path, tail=False):
    try:
        with open(path,'rb') as f:
            if tail: f.seek(max(0,os.fstat(f.fileno()).st_size-CAP))
            return f.read(CAP).decode('utf-8','replace')
    except OSError: return ''
def run(*args):
    if args in RUN_OUTPUT: return RUN_OUTPUT[args]
    if time.monotonic()-START>DEADLINE:
        RUN_META[args]='budget exceeded'; return ''
    if not shutil.which(args[0]) and not os.path.isfile(args[0]):
        RUN_META[args]='not installed'; return ''
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
        RUN_META[args]=p.returncode
        if p.returncode not in (0,100): return ''
        result=out.decode('utf-8','replace'); RUN_OUTPUT[args]=result
        return result
    except (OSError,ValueError) as e:
        RUN_META[args]='command error'; return ''
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
    SECTIONS.setdefault(section,{})[label]=status+' - '+re.sub(r'[\x00-\x1f\x7f]', ' ', str(details).replace('\n','; '))[:2200]
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
    jobs_response=jrun(binary,'-F','listBackupJobs','-O','json')
    jobs=objects(jobs_response,'jobs')
    total=jobs_response.get('data',{}).get('total') if isinstance(jobs_response.get('data'),dict) else None
    complete=str(total).isdigit() and int(total)==len(jobs)
    destinations=objects(jrun(binary,'-F','listDestinations','-O','json'),'destinations')
    schedules=objects(jrun(binary,'-F','listSchedules','-O','json'),'schedules')
    smap={s.get('_id'):s for s in schedules}
    dmap={d.get('_id'):d for d in destinations}
    active=[j for j in jobs if not enabled(j.get('disabled'))]
    if not jobs:
        for label in ['Local Backup','Remote Backup','Daily Backup','Weekly Backup','Monthly Backup','Recent Last Backup']:
            previous=SECTIONS.get('4. Backup',{}).get(label,'Unknown - No native evidence')
            SECTIONS.setdefault('4. Backup',{})[label]=previous+'; JetBackup detected but API unreadable/empty'
        return True
    frequencies={2:[],3:[],4:[]}; local=[]; remote=[]; statuses=[]; jobnotes=[]
    sizes=[]
    schedule_complete=complete and all('schedules' in j for j in active)
    destination_complete=complete and all('destination_details' in j or all(i in dmap for i in aslist(j.get('destination',[]))) for j in active)
    for job in active[:20]:
        name=str(job.get('name',job.get('_id','job')))[:100]
        for sched in aslist(job.get('schedules',[])):
            s=dict(smap.get(sched.get('_id'),{}),**sched) if isinstance(sched,dict) else smap.get(sched,{})
            try: t=int(s.get('type',0))
            except (ValueError,TypeError): t=0
            if t in frequencies and not enabled(s.get('disabled')): frequencies[t].append(name+'; days='+str(s.get('type_data','unspecified')))
        for dest in aslist(job.get('destination_details',[])) or [dmap.get(i,{}) for i in aslist(job.get('destination',[]))]:
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
            sm=re.findall(r'(?im)\b(?:total backup size|backup size)\s*[:=]\s*([0-9.,]+\s*(?:bytes?|[KMGT]i?B))\b',tail)
            if sm: sizes.append(name+': '+sm[-1]+'; log='+logpath)
            failures=[line[:150] for line in tail.splitlines() if re.search(r'\b(error|failed|aborted|partial)\b',line,re.I) and not re.search(r'(?:errors?|failed)\s*[:=]\s*0\b|no errors?|0 (?:errors?|failed)',line,re.I)]
            if failures:
                note+='; log findings: '+' | '.join(failures[-3:]); statuses[-1]='Warning'
        jobnotes.append(note)
    if len(active)>20:
        statuses.append('Unknown'); jobnotes.append('Only first 20 enabled jobs inspected; overall coverage incomplete')
    for label,vals in [('Local Backup',local),('Remote Backup',remote)]:
        put('4. Backup',label,'Good' if vals else 'Not applicable' if destination_complete else 'Unknown','JetBackup enabled job destinations: '+' | '.join(vals) if vals else 'No enabled destination of this kind in the complete job list' if destination_complete else 'No matching enabled destination proven; listing completeness unknown')
    for t,label in [(2,'Daily Backup'),(3,'Weekly Backup'),(4,'Monthly Backup')]:
        put('4. Backup',label,'Good' if frequencies[t] else 'Disabled' if schedule_complete else 'Unknown','JetBackup configured '+label+': '+' | '.join(frequencies[t]) if frequencies[t] else 'No '+label+' schedule in complete enabled-job list' if schedule_complete else 'No '+label+' schedule established; listing completeness unknown')
    put('4. Backup','Recent Last Backup','Warning' if 'Warning' in statuses else 'Unknown' if not statuses or 'Unknown' in statuses else 'Good',' | '.join(jobnotes) or 'No enabled job results; maximum 20 jobs inspected')
    put('4. Backup','Size Of Last Backup','Good' if sizes and len(sizes)==len(active) else 'Review', 'Explicit per-job size summaries: '+' | '.join(sizes) if sizes else 'No explicit per-run size summary in returned API/logs; storage capacity is not backup size; metadata-only checks avoid full backup directory walks')
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
    ap.add_argument('--offline',action='store_true',help='Skip public vendor HTTPS and DNS queries')
    ap.add_argument('--public-ip',default='',help='Override public IPv4 for PTR/DNSBL checks')
    ap.add_argument('--backup-log',action='append',default=[],help='Custom existing backup log path')
    ap.add_argument('--malware-report',default=''); ap.add_argument('--cms-report',default='')
    ap.add_argument('--cms-root',action='append',default=[],help='Additional document root; bounded metadata discovery')
    ap.add_argument('--choose',action='store_true'); ap.add_argument('--format',choices=['text','json'],default='text')
    ap.add_argument('--max-seconds',type=int,default=120); ap.add_argument('--report-max-age-days',type=int,default=14)
    ap.add_argument('--backup-max-age-days',type=int,default=8)
    a=ap.parse_args(); DEADLINE=max(10,min(a.max_seconds,600))
    panel=a.panel
    if a.choose:
        print('1 cPanel / 2 Plesk / 3 Non-panel / 4 DirectAdmin / 0 Auto',file=sys.stderr)
        print('Panel: ',end='',file=sys.stderr,flush=True)
        try:
            with open('/dev/tty') as tty: answer=tty.readline().strip()
        except OSError: answer=input().strip()
        panel={'1':'cpanel','2':'plesk','3':'none','4':'directadmin','0':'auto'}.get(answer,'auto')
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
    ends={('cloudlinux','8'):'2029-05-31',('cloudlinux','9'):'2032-05-31',('cloudlinux','10'):'2035-05-31',('almalinux','10'):'2035-05-31',('centos','7'):'2024-06-30',('cloudlinux','7'):'2024-06-30',('almalinux','8'):'2029-03-01',('almalinux','9'):'2032-05-31',('rocky','8'):'2029-05-31',('rocky','9'):'2032-05-31',('ubuntu','20'):'2025-05-31',('ubuntu','22'):'2027-05-31',('ubuntu','24'):'2029-05-31',('debian','11'):'2026-08-31',('debian','12'):'2028-06-30'}
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
    enhanced(a,panel,system,units,packages,v)
    if a.format=='json': print(json.dumps({'schema':'linux-audit-v7','system':system,'sections':SECTIONS},indent=2))
    else:
        print('DETAILED TECHNICAL LOG\n======================\nGenerated: '+system['Generated']+'\n\n=== System Information ===')
        for k,vv in system.items():
            if k!='Generated': print('{:22}: {}'.format(k,vv))
        for section in sorted(SECTIONS):
            print('\n=== '+section+' ===')
            for k,vv in SECTIONS[section].items(): print('{:24}: {}'.format(k,vv))
        print('\nAudit Complete! v7 read-only; elapsed {:.1f}s; unavailable/ambiguous evidence remains Unknown.'.format(time.monotonic()-START))

def aslist(value):
    if isinstance(value,dict): return list(value.values())
    return value if isinstance(value,list) else []

def fetch(url):
    """Bounded HTTPS GET only, in memory; no remote script execution."""
    if url in NET_CACHE: return NET_CACHE[url]
    if not ONLINE or time.monotonic()-START>=DEADLINE: return ''
    import urllib.request
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'LinuxAudit/7.0'})
        with urllib.request.urlopen(request,timeout=min(4,max(.2,DEADLINE-(time.monotonic()-START)))) as response:
            value=response.read(1048576).decode('utf-8','replace')
    except Exception: value=''
    NET_CACHE[url]=value
    return value

def package_group(name):
    if re.search(r'(?:php|php-fpm)',name,re.I): return 'PHP'
    if re.search(r'^(?:ea-)?(?:httpd|apache|nginx|lshttpd|litespeed|lsws)(?:[-.]|$)',name,re.I): return 'Web Server'
    if re.search(r'(?:mysql|mariadb|postgresql|percona)',name,re.I): return 'Database Server'
    if re.search(r'^(?:cpanel|psa|plesk|sw-cp-server|sw-engine|directadmin)(?:[-.]|$)',name,re.I): return 'Panel packages'
    return 'Other Softwares'

def parse_updates(text,rpm=False):
    rows=[]
    for line in text.splitlines():
        if rpm:
            m=re.match(r'^\s*([A-Za-z0-9_+.-]+)\.(?:x86_64|noarch|i[3-6]86|aarch64|armv7hl|ppc64le|s390x)\s+(\S+)\s+(\S+)',line)
        else:
            m=re.match(r'^([A-Za-z0-9_.+:-]+)/\S+\s+(\S+)\s+(\S+).*\[upgradable from:',line)
        if m: rows.append((m.group(1),m.group(2),m.group(3)))
    return list(dict.fromkeys(rows))

def update_checks(packages):
    rpm=bool(shutil.which('rpm'))
    args=('dnf','-C','check-update','--quiet') if shutil.which('dnf') else ('yum','-C','check-update','--quiet') if shutil.which('yum') else ('apt','list','--upgradable')
    text=run(*args); rc=RUN_META.get(args,'unavailable'); rows=parse_updates(text,rpm)
    installed=[line.split()[0] for line in packages.splitlines() if line.split()]
    okay=rc in (0,100) and (bool(rows) or rc==0)
    roots=['/var/cache/dnf','/var/cache/yum'] if rpm else ['/var/lib/apt/lists']
    cachefiles=latest_files(roots,r'repomd.xml$|primary.*(?:sqlite|xml|solv)|(?:InRelease|Release|Packages.*)$',1)
    cachedate=dt.datetime.utcfromtimestamp(cachefiles[0][0]).isoformat()+' UTC' if cachefiles else 'not established'
    fresh=bool(cachefiles) and 0<=(time.time()-cachefiles[0][0])/86400<=2
    suffix='; cached repository data only (no refresh); newest metadata='+cachedate
    if okay:
        put('2. Software Updates','Operating System','Warning' if rows else 'Good' if fresh else 'Review',str(len(rows))+' package update(s) in cached metadata'+suffix)
    else: unknown('2. Software Updates','Operating System','Package query incomplete; result='+str(rc)+suffix)
    for label in ['PHP','Web Server','Database Server','Other Softwares']:
        selected=[r for r in rows if package_group(r[0])==label]
        present=any(package_group(n)==label for n in installed)
        if not okay: unknown('2. Software Updates',label,'Package query incomplete; result='+str(rc)+suffix)
        elif label!='Other Softwares' and not present and not selected and packages:
            put('2. Software Updates',label,'Not applicable','No corresponding installed package in inventory; custom/source installs checked by service inventory')
        else: put('2. Software Updates',label,'Warning' if selected else 'Good' if fresh else 'Review',str(len(selected))+' cached update(s): '+', '.join(r[0]+' -> '+r[1] for r in selected[:12])+suffix)
    return rows

def version_tuple(v):
    return tuple(int(x) for x in re.findall(r'\d+',re.sub(r'^11\.','',v)))

def panel_checks(panel,system,v,rows):
    display=system['Control Panel']; update='2. Software Updates'; life='5. Software Life Time'
    if panel=='none':
        put(update,'Control Panel','Not applicable','No control panel installed/detected')
        put(life,'Control Panel','Not applicable','No control panel installed/detected'); return
    if panel=='cpanel' and v:
        tier=cfg('/etc/cpupdate.conf').get('cpanel','release').lower()
        text=fetch('https://httpupdate.cpanel.net/cpanelsync/TIERS') or read('/var/cpanel/cpanel.version.tiers')
        tiers=dict(re.findall(r'(?m)^([A-Za-z0-9_-]+):\s*([\d.]+)',text))
        latest=tiers.get(tier)
        if latest:
            installed=tuple(map(int,v.groups())); available=version_tuple(latest)
            put(update,'Control Panel','Warning' if installed<available else 'Good' if installed==available else 'Review',display+'; tier='+tier+'; target='+latest+'; '+('live vendor GET' if ONLINE and NET_CACHE.get('https://httpupdate.cpanel.net/cpanelsync/TIERS') else 'local tier cache')+'; major upgrades may have OS blockers')
        else: unknown(update,'Control Panel',display+'; vendor tier unavailable/unknown: '+tier)
        major=int(v.group(1)); today=dt.date.today()
        # Presence in a live production tier is direct support evidence. Old release dates are approximate.
        prod={version_tuple(x)[0] for k,x in tiers.items() if k in ['release','stable','current','lts'] and version_tuple(x)}
        if major==110:
            put(life,'Control Panel','Warning','cPanel 110 limited ELS through 2027-01-01 on eligible CentOS/CloudLinux 7; migration required; '+display)
        elif ONLINE and major in prod:
            put(life,'Control Panel','Good',display+'; branch present in live vendor production tiers; https://httpupdate.cpanel.net/cpanelsync/TIERS')
        elif major==134 and today<=dt.date(2027,6,30):
            put(life,'Control Panel','Good',display+'; documented LTS approximate EOL June 2027; policy snapshot 2026-10-02')
        elif major==136 and today>=dt.date(2026,9,1):
            put(life,'Control Panel','Warning',display+'; vendor approximate EOL August 2026; not proven in live production tiers; verify RELEASE transition and migrate')
        elif major==138 and today<dt.date(2026,11,1):
            put(life,'Control Panel','Good',display+'; documented approximate EOL November 2026; policy snapshot 2026-10-02')
        elif major<134:
            put(life,'Control Panel','Warning',display+'; older branch outside maintained lifecycle catalogue; verify vendor support')
        else: unknown(life,'Control Panel',display+'; branch not established from current vendor data')
    elif panel=='plesk':
        target=read('/usr/local/psa/version') or display
        put(life,'Control Panel','Good' if re.search(r'\b18\.',target) else 'Warning',display+'; '+('Obsidian 18 major branch maintained; individual release currency checked separately' if re.search(r'\b18\.',target) else 'Older Plesk major; lifecycle review required')+'; https://www.plesk.com/lifecycle-policy/')
        pending=[r for r in rows if package_group(r[0])=='Panel packages']
        put(update,'Control Panel','Warning' if pending else 'Review',display+'; '+str(len(pending))+' cached Plesk-family package update(s); installer-only updates not independently queried')
    else:
        target=fetch('https://current-version.directadmin.com/')
        latest=re.search(r'\b1\.\d+(?:\.\d+)?\b',target)
        installed=re.search(r'\b1\.\d+(?:\.\d+)?\b',display)
        if latest and installed:
            state='Warning' if version_tuple(installed.group())<version_tuple(latest.group()) else 'Good'
            put(update,'Control Panel',state,display+'; vendor current channel='+latest.group()+'; selected update channel may differ')
            put(life,'Control Panel','Good' if state=='Good' else 'Review','DirectAdmin current-channel comparison; older build is not automatically EOL; '+display)
        else: unknown(update,'Control Panel',display+'; current-channel data unavailable')

def parse_scan_text(text,kind):
    """Recognize explicit summaries; negated findings never become infections."""
    if not text.strip(): return 'Unknown','Empty report'
    try:
        d=json.loads(text)
        if isinstance(d,dict):
            for key in (['infected_files','malware_count','infected','findings_count'] if kind=='malware' else ['outdated_count','outdated_cms']):
                value=d.get(key)
                if isinstance(value,int) and not isinstance(value,bool):
                    return ('Warning','Explicit '+key+'='+str(value)) if value>0 else ('Good','Explicit '+key+'=0')
    except ValueError: pass
    lines=text.splitlines()
    if re.search(r'(?im)^.*(?:scan|scanner|freshclam).*(?:failed|aborted)|^\s*(?:ERROR|FATAL)\s*:',text):
        return 'Warning','Scan/check errors present; completion not established'
    if kind=='malware':
        counters=re.findall(r'(?im)^\s*(?:[-*# ]*)?(?:infected files|(?:total )?(?:malware|malicious|suspicious|infected)(?: (?:files|items|found|detected))?|total threats)\s*[:=]\s*(\d+)\b',text)
        if any(int(n)>0 for n in counters): return 'Warning','Positive infected/suspicious count='+str(max(map(int,counters)))
        bad=[l for l in lines if re.match(r'^\s*File:\s*/',l) or re.search(r'\bFOUND\s*$',l) and not re.search(r'(?i)\b(?:no|not|0)\s+(?:malware\s+)?found',l)]
        if bad: return 'Warning','Finding entry: '+bad[0][:160]
        if counters and all(int(n)==0 for n in counters): return 'Good','Explicit zero infected/suspicious summary'
        if re.search(r'(?im)^\s*(?:malware|ClamAV|malware status)\s*[:=]\s*(?:clean|none|not detected)\b',text): return 'Good','Explicit clean malware status'
        if re.search(r'(?i)\b(?:no malware|no infected files|no suspicious files|no threats|no infections)\s+(?:were\s+)?(?:found|detected)|scan (?:completed|finished).*\bclean\b',text): return 'Good','Explicit clean summary'
    else:
        counters=re.findall(r'(?im)^\s*(?:total\s+)?outdated (?:CMS|packages?|installations?|software)(?: count)?\s*[:=]\s*(\d+)\b',text)
        if any(int(n)>0 for n in counters): return 'Warning','Positive outdated count='+str(max(map(int,counters)))
        bad=[l for l in lines if re.search(r'(?i)\b(?:wordpress|joomla|drupal|magento|phpmailer|cms)\b.*\b(?:outdated|unsupported|EOL)\b',l) and not re.search(r'(?i)\bno outdated|\bnot outdated',l)]
        if bad: return 'Warning','Outdated entry: '+bad[0][:160]
        if counters or re.search(r'(?i)\bno outdated (?:CMS|packages?|software|installations?)|all (?:CMS|packages?|installations?) (?:are )?(?:up.to.date|supported)',text): return 'Good','Explicit current/zero outdated summary'
    return 'Review','Report exists; no recognized explicit verdict (use --'+('malware' if kind=='malware' else 'cms')+'-report to select a custom report)'

def scan_report(kind,days,path=''):
    pattern=r'(?:cms|outdated|wordpress|joomla).*\.(?:txt|log|json)$' if kind=='cms' else r'(?:malware|scan).*(?:report|result|detail).*\.(?:txt|log|json)$'
    if path:
        try: candidates=[(os.stat(path).st_mtime,path)]
        except OSError: return 'Unknown','Specified report unreadable: '+path
    else: candidates=latest_files(['/root/scripts'],pattern)
    if kind=='malware': candidates=[x for x in candidates if not re.search(r'cms|outdated|rootkit',os.path.basename(x[1]),re.I)]
    if not candidates: return 'Review','No completed '+kind+' report detected under /root/scripts; no scan was started'
    modified,path=candidates[0]; age=(time.time()-modified)/86400
    state,note=parse_scan_text(read(path,True),kind)
    if age<0: state='Review';note+='; future report mtime/clock mismatch'
    elif age>days: state='Warning';note+='; stale report'
    return state,note+'; path='+path+'; mtime='+dt.datetime.utcfromtimestamp(modified).isoformat()+' UTC; age={:.1f}d; read capped at 256 KiB; mtime is not proof of completion/coverage'.format(age)

def cms_inventory(extra_roots):
    roots=list(extra_roots)
    # Only parse metadata; never execute site PHP, wp-cli or account-owned scripts.
    users=glob.glob('/var/cpanel/userdata/*')[:500]
    for base in users:
        for file in glob.glob(base+'/*')[:25]:
            if os.path.isfile(file) and not file.endswith(('.cache','.json')):
                roots.extend(re.findall(r'(?m)^\s*documentroot:\s*(/[^\n]+)',read(file)))
    roots+=['/var/www/html','/var/www/vhosts','/home']
    found=[];seen=set();entries=0;complete=True
    for root in dict.fromkeys(roots):
        if not os.path.isdir(root): continue
        for base,dirs,files in os.walk(root,followlinks=False):
            entries+=len(dirs)+len(files)
            dirs[:]=[d for d in dirs if not os.path.islink(os.path.join(base,d)) and d not in ['node_modules','vendor','cache','logs','mail','tmp','.git','wp-content','wp-admin','backups']]
            if base[len(root):].count(os.sep)>=5: dirs[:]=[];complete=False
            if 'version.php' in files and base.endswith('/wp-includes'):
                path=base+'/version.php'; match=re.search(r"\$wp_version\s*=\s*['\"]([\d.]+)['\"]",read(path))
                if match and path not in seen: found.append(('WordPress',match.group(1),path));seen.add(path)
                dirs[:]=[]
            if base.endswith('/includes') and 'version.php' in files:
                path=base+'/version.php';text=read(path)
                match=re.search(r"\$RELEASE\s*=\s*['\"]([\d.]+)['\"]",text)
                dev=re.search(r"\$DEV_LEVEL\s*=\s*['\"]([\d.]+)['\"]",text)
                if match and path not in seen: found.append(('Joomla',match.group(1)+('.'+dev.group(1) if dev else ''),path));seen.add(path)
            if entries>=5000 or len(found)>=100: complete=False;break
        if entries>=5000 or len(found)>=100: break
    return found,complete

def cms_checks(a):
    report=scan_report('cms',a.report_max_age_days,a.cms_report)
    inventory,complete=cms_inventory(a.cms_root)
    latest=''
    if any(x[0]=='WordPress' for x in inventory):
        try:
            offers=json.loads(fetch('https://api.wordpress.org/core/version-check/1.7/')).get('offers',[])
            latest=next((x.get('version','') for x in offers if x.get('response')=='upgrade'),'')
        except (ValueError,AttributeError): pass
    old=[x for x in inventory if x[0]=='WordPress' and latest and version_tuple(x[1])<version_tuple(latest)]
    details='; metadata inventory='+', '.join(x[0]+' '+x[1]+' @ '+x[2] for x in inventory[:12])+'; discovery '+('within bounds' if complete else 'limited/truncated')
    if old: state='Warning';note='WordPress older than latest '+latest+' ('+str(len(old))+' discovered); '+report[1]
    elif report[0] in ['Good','Warning']: state,note=report
    elif inventory and latest and all(x[0]=='WordPress' and version_tuple(x[1])>=version_tuple(latest) for x in inventory):
        state='Good' if complete else 'Review';note='Discovered WordPress installations match latest '+latest+'; bounded discovery is not proof of all accounts'
    elif inventory: state='Review';note='CMS versions found; latest vendor/reference unavailable; '+report[1]
    else: state='Review';note='No CMS report/recognized CMS metadata found in bounded roots; role/coverage not established'
    put('2. Software Updates','CMS',state,note+details)
    # Current-version evidence is not equivalent to a lifecycle guarantee for arbitrary CMS packages.
    put('5. Software Life Time','CMS','Warning' if report[0]=='Warning' or old else 'Good' if report[0]=='Good' else 'Review',report[1]+details+'; update status and vendor lifecycle may differ')

def dns_query(name,qtype):
    """Small bounded UDP DNS client; no dependency on dig; A/PTR only."""
    import socket,struct,secrets
    if not ONLINE or time.monotonic()-START>=DEADLINE: return 'offline',[]
    servers=re.findall(r'(?m)^nameserver\s+(\S+)',read('/etc/resolv.conf'))[:2]
    def unpack_name(data,offset,visited=None):
        visited=set() if visited is None else visited;labels=[];nextpos=None
        while True:
            if offset>=len(data) or offset in visited: raise ValueError('bad DNS name')
            visited.add(offset);length=data[offset]
            if length&192==192:
                pointer=((length&63)<<8)|data[offset+1]
                if nextpos is None: nextpos=offset+2
                nested,_=unpack_name(data,pointer,visited);labels.append(nested);break
            offset+=1
            if not length: break
            labels.append(data[offset:offset+length].decode('ascii','replace'));offset+=length
        return '.'.join(labels),nextpos if nextpos is not None else offset
    for server in servers:
        try:
            ident=secrets.randbelow(65536);labels=name.strip('.').split('.')
            wire=b''.join(bytes([len(x)])+x.encode('ascii') for x in labels)+b'\0'
            request=struct.pack('!HHHHHH',ident,256,1,0,0,0)+wire+struct.pack('!HH',qtype,1)
            family=socket.AF_INET6 if ':' in server else socket.AF_INET
            with socket.socket(family,socket.SOCK_DGRAM) as sock:
                sock.settimeout(min(1.5,max(.1,DEADLINE-(time.monotonic()-START))))
                sock.connect((server,53));sock.send(request);data=sock.recv(4096)
            rid,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',data[:12])
            if rid!=ident or not flags&32768 or flags&512: continue
            code=flags&15
            if code==3:return 'nxdomain',[]
            if code:return 'DNS rcode '+str(code),[]
            offset=12
            for _ in range(qd): _,offset=unpack_name(data,offset);offset+=4
            answers=[]
            for _ in range(min(an,100)):
                _,offset=unpack_name(data,offset);typ,cls,ttl,length=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
                if typ==1 and length==4: answers.append(socket.inet_ntoa(data[offset:offset+4]))
                elif typ==12: answers.append(unpack_name(data,offset)[0])
                offset+=length
            return 'ok',answers
        except (OSError,ValueError,IndexError,struct.error,UnicodeError): continue
    return 'DNS unavailable/timeout',[]

def network_checks(a,system):
    import ipaddress
    route=run('ip','-4','route','get','1.1.1.1');m=re.search(r'\bsrc\s+([\d.]+)',route)
    ip=a.public_ip or (m.group(1) if m else '')
    system['Main IP']=ip or 'Not detected'
    if not ip: unknown('6. Proactive Defence','IP RDNS','No IPv4 route/source; pass --public-ip');return
    try: addr=ipaddress.ip_address(ip)
    except ValueError: unknown('6. Proactive Defence','IP RDNS','Invalid --public-ip');return
    status,ptr=dns_query('.'.join(reversed(ip.split('.')))+'.in-addr.arpa',12)
    if ptr:
        fs,ips=dns_query(ptr[0],1)
        put('6. Proactive Defence','IP RDNS','Good' if ip in ips else 'Warning' if fs in ['ok','nxdomain'] else 'Review','IP='+ip+'; PTR='+ptr[0]+'; forward-confirmed='+str(ip in ips))
    elif status in ['ok','nxdomain']: put('6. Proactive Defence','IP RDNS','Warning','No PTR returned for '+ip)
    else: unknown('6. Proactive Defence','IP RDNS',status+'; IP='+ip)
    if not addr.is_global:
        put('3. Server Health','IP Reputation','Not applicable','Private/non-global source '+ip+'; pass --public-ip for NAT/public egress checks');return
    zone='bl.spamcop.net';ds,listed=dns_query('.'.join(reversed(ip.split('.')))+'.'+zone,1)
    hits=[x for x in listed if x.startswith('127.')]
    put('3. Server Health','IP Reputation','Warning' if hits else 'Good' if ds in ['ok','nxdomain'] else 'Unknown','SpamCop only: '+('listed '+str(hits) if hits else 'not listed' if ds in ['ok','nxdomain'] else ds)+'; not a comprehensive reputation assessment; resolver blocking remains possible')

def health_container(system):
    virt=run('systemd-detect-virt','--container').strip(); container=bool(virt and virt!='none')
    system['System Type']='Container ('+virt+')' if container else run('systemd-detect-virt').strip() or 'Physical/undetected'
    if container:
        put('3. Server Health','CPU Usage','Review','Container '+virt+'; /proc load may include host work; no host load divided by container CPU count')
        # Resolve current process cgroup relative to mount rather than assuming the host root is this container.
        cg=next((l.split(':',2)[2] for l in read('/proc/self/cgroup').splitlines() if l.startswith('0::')),'')
        base='/sys/fs/cgroup'+cg
        if not os.path.isfile(base+'/memory.current'): base='/sys/fs/cgroup'
        current=read(base+'/memory.current').strip();limit=read(base+'/memory.max').strip()
        if current.isdigit() and limit.isdigit() and int(limit)>0:
            ratio=100*int(current)/int(limit)
            put('3. Server Health','RAM Usage','Warning' if ratio>90 else 'Good','Container cgroup v2 memory {:.1f}%; current={}; limit={}'.format(ratio,current,limit))
        else: put('3. Server Health','RAM Usage','Review','Container memory limit unavailable/unlimited; /proc/meminfo may be host-wide')
    uptime=read('/proc/uptime').split(' ')[0]
    try:
        days=float(uptime)/86400
        put('3. Server Health','Server Uptime','Review' if container else 'Good','{:.1f} days; '.format(days)+('kernel uptime may reflect container host' if container else 'kernel uptime'))
    except ValueError: pass

def firewall_checks(units,packages):
    active=lambda name: bool(re.search(r'(?m)^\s*'+re.escape(name)+r'\.service\s',units))
    imu=any(active(n) for n in ['imunify360','imunify360-agent','imunify360-firewall'])
    if not imu:
        ufw=run('ufw','status')
        nft=run('nft','list','ruleset')
        ipt=run('iptables','-S')
        filters=re.findall(r'(?im)^.*(?:\bdrop\b|\breject\b|\bpolicy drop\b|-P \S+ (?:DROP|REJECT)).*$',nft+'\n'+ipt)
        success=any(RUN_META.get(args)==0 for args in [('ufw','status'),('nft','list','ruleset'),('iptables','-S')])
        if re.search(r'Status:\s*active',ufw,re.I) or filters:
            put('1. Threat Protection','System Firewall','Good','UFW active or kernel DROP/REJECT rules present; '+str(len(filters))+' filtering rule(s); not an end-to-end reachability test')
        elif success: put('1. Threat Protection','System Firewall','Warning','Readable firewall state has no active UFW or DROP/REJECT rules; cloud/provider firewall not visible')
        elif not any(shutil.which(x) for x in ['ufw','nft','iptables']): put('1. Threat Protection','System Firewall','Warning','No supported local firewall query tool installed; provider firewall unknown')
    detectors=[n for n in ['lfd','fail2ban','cphulkd'] if active(n)]
    if not imu and not detectors:
        put('1. Threat Protection','Failed Login Detection','Warning' if units else 'Unknown','No running known local login detector in available service inventory; provider controls unknown')
    scanners=[p for p in ['/usr/local/cpanel/3rdparty/bin/clamscan','/usr/bin/clamscan','/usr/local/maldetect/maldet','/usr/bin/imunify-antivirus'] if os.path.isfile(p)]
    scanners+=[shutil.which(x) for x in ['clamscan','maldet','imunify-antivirus'] if shutil.which(x)]
    if not imu:
        put('1. Threat Protection','Malware Scanner','Good' if scanners else 'Warning','Installed CLI scanner(s): '+', '.join(dict.fromkeys(scanners))+'; installation does not prove scheduling or recent clean scan' if scanners else 'No known local scanner binary detected; no software installed by audit')
    rootkits=[x for x in ['rkhunter','chkrootkit'] if shutil.which(x)]
    put('1. Threat Protection','Rootkit Scanner','Good' if rootkits else 'Warning','Installed: '+', '.join(rootkits)+'; results checked separately' if rootkits else 'No rkhunter/chkrootkit binary detected')
    if not imu:
        # Bounded config inspection, not apache/nginx config-test commands that open log files.
        confs=glob.glob('/etc/apache2/mods-enabled/*security*.conf')+glob.glob('/etc/httpd/conf.d/*security*.conf')+glob.glob('/etc/apache2/conf.d/*modsec*.conf')+glob.glob('/etc/nginx/*modsec*.conf')
        confs+=['/etc/apache2/mods-enabled/security2.load','/etc/httpd/conf.modules.d/00-mod_security.conf']
        text='\n'.join(read(f) for f in confs[:30])
        on=bool(re.search(r'(?im)^\s*(?:SecRuleEngine\s+On|modsecurity\s+on)',text))
        loaded=bool(re.search(r'(?im)^\s*LoadModule\s+security2_module',text)) or bool(re.search(r'(?im)^\s*modsecurity\s+on',text))
        if on and loaded: put('1. Threat Protection','Web App Firewall','Good','ModSecurity module and blocking-mode directives in enabled config candidates; per-vhost overrides need review')
        elif re.search(r'(?im)^\s*SecRuleEngine\s+(?:Off|DetectionOnly)',text): put('1. Threat Protection','Web App Firewall','Warning','ModSecurity Off/DetectionOnly directive found; no blocking protection proven')
        elif not re.search(r'(?:apache|httpd|nginx|lshttpd|litespeed)',packages,re.I) and not any(shutil.which(x) for x in ['nginx','httpd','apache2']):
            put('1. Threat Protection','Web App Firewall','Not applicable','No supported local web-server package/binary detected; custom/containerized services not excluded')
        else: put('1. Threat Protection','Web App Firewall','Review','Web server detected; no enabled blocking WAF established from standard configuration')


def php_security(packages):
    hasphp=bool(re.search(r'(?m)^\S*php\S*\s',packages)) or bool(shutil.which('php'))
    if not hasphp: put('6. Proactive Defence','PHP Functions Security','Not applicable','No installed PHP package/binary detected');return
    patterns=['/etc/php.ini','/etc/php/*/fpm/php.ini','/etc/php/*/apache2/php.ini','/etc/php/*/fpm/pool.d/*.conf','/etc/php.d/*.ini','/opt/cpanel/ea-php*/root/etc/php.ini','/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf','/opt/alt/php*/etc/php.ini','/opt/plesk/php/*/etc/php.ini','/usr/local/php*/lib/php.ini','/usr/local/php*/etc/php-fpm.d/*.conf']
    files=list(dict.fromkeys(p for pattern in patterns for p in glob.glob(pattern)))[:150]
    dangerous={'exec','shell_exec','system','passthru','popen','proc_open'};findings=[];observed=[]
    for p in files:
        values=re.findall(r'(?im)^\s*(?:disable_functions|php_(?:admin_)?value\[disable_functions\])\s*=\s*([^;\n]*)',read(p))
        if not values: continue
        disabled=set(x.strip().strip('\"\'') for x in values[-1].strip().strip('\"\'').split(','));missing=dangerous-disabled
        observed.append(p)
        if missing: findings.append(p+': missing '+','.join(sorted(missing)))
    if findings: put('6. Proactive Defence','PHP Functions Security','Warning','Baseline hardening absent in sampled files: '+' | '.join(findings[:8])+'; disable_functions alone is not a security boundary; web-SAPI/per-domain overrides require review')
    elif observed: put('6. Proactive Defence','PHP Functions Security','Review','Dangerous functions disabled in '+str(len(observed))+' sampled files; active web SAPI and overrides not fully resolved')
    else: put('6. Proactive Defence','PHP Functions Security','Review','PHP installed, no disable_functions setting found in sampled standard files; web SAPI configuration needs review')

def extra_backup_logs(paths,days):
    if not paths:return
    notes=[];states=[]
    for path in paths[:10]:
        try: modified=os.stat(path).st_mtime
        except OSError: states.append('Unknown');notes.append(path+': unreadable');continue
        text=read(path,True)
        state,note=parse_backup_text(text)
        if (time.time()-modified)/86400>days: state='Warning';note+='; stale log'
        notes.append(path+': '+note);states.append(state)
    put('4. Backup','Recent Last Backup','Warning' if 'Warning' in states else 'Unknown' if 'Unknown' in states else 'Review','Custom log review (does not override destination/job integrity): '+' | '.join(notes))

def parse_backup_text(text):
    lines=[l for l in text.splitlines() if re.search(r'(?i)\b(?:error|failed|aborted|partial)\b',l) and not re.search(r'(?i)(?:errors?|failed)\s*[:=]\s*0\b|no errors?|0 (?:errors?|failed)',l)]
    if lines:return 'Warning','Failure marker: '+lines[-1][:180]
    if re.search(r'(?i)(?:backup|transport|task).*(?:completed successfully|finished successfully)|Backup process completed',text):return 'Review','Completion marker found; job/destination/account coverage unverified'
    return 'Unknown','No explicit terminal backup result in bounded tail'

def backup_schedule_fallback(panel):
    # Preserve authoritative panel/JetBackup decisions. Identify configured periodic cron cadence.
    jet_present=bool(shutil.which('jetbackup5api')) or os.path.isfile('/usr/local/jetapps/usr/bin/jetbackup5api')
    if jet_present or panel=='cpanel':return
    text=run('crontab','-l')+'\n'+read('/etc/crontab')
    for p in glob.glob('/etc/cron.d/*')[:100]:text+='\n'+read(p)
    freqs={};candidates=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#') or not re.search(r'(?i)backup|borg|restic|duplicity|rclone',line):continue
        candidates.append(line)
        if line.startswith('@daily'):cad='Daily Backup'
        elif line.startswith('@weekly'):cad='Weekly Backup'
        elif line.startswith('@monthly'):cad='Monthly Backup'
        else:
            fields=line.split()
            if len(fields)<6:continue
            minute,hour,dom,month,dow=fields[:5]
            cad='Daily Backup' if dom=='*' and dow=='*' and re.fullmatch(r'\d+',hour) else 'Weekly Backup' if dom=='*' and re.fullmatch(r'\d+',dow) else 'Monthly Backup' if re.fullmatch(r'\d+',dom) and month=='*' and dow=='*' else None
        if cad: freqs.setdefault(cad,[]).append('cron entry detected')
    for folder,cad in [('/etc/cron.daily','Daily Backup'),('/etc/cron.weekly','Weekly Backup'),('/etc/cron.monthly','Monthly Backup')]:
        for p in glob.glob(folder+'/*')[:60]:
            if os.path.isfile(p) and os.path.basename(p) not in ['dpkg','apt','apt-compat','logrotate'] and re.search(r'(?i)borg|restic|duplicity|rclone|(?:rsync|tar).*backup|pleskbackup|backupmng|jetbackup',read(p)):
                freqs.setdefault(cad,[]).append(p)
    for cad,notes in freqs.items():put('4. Backup',cad,'Good','Configured periodic backup candidate(s): '+' | '.join(notes)+'; execution/success not implied')
    if not candidates and not freqs:
        for cad in ['Daily Backup','Weekly Backup','Monthly Backup']:put('4. Backup',cad,'Review','No standard local backup schedule detected; provider/Proxmox backups may be external to this server')


def enhanced(a,panel,system,units,packages,v):
    global ONLINE
    ONLINE=not a.offline
    system['Audit Version']='7.0';system['Network Checks']='Disabled' if a.offline else 'Read-only vendor HTTPS GET and DNS; no report upload'
    rows=update_checks(packages);panel_checks(panel,system,v,rows)
    firewall_checks(units,packages);cms_checks(a)
    put('6. Proactive Defence','Malware Scan',*scan_report('malware',a.report_max_age_days,a.malware_report))
    rkhpath='/var/log/rkhunter.log' if os.path.isfile('/var/log/rkhunter.log') else '/var/log/rkhunter/rkhunter.log'
    rkh=read(rkhpath,True)
    warn=[l for l in rkh.splitlines() if re.search(r'(?i)\bwarning\b',l) and not re.search(r'(?i)no warnings?|warnings?\s*[:=]\s*0\b|warnings?\s*[:=]\s*none\b',l)]
    if warn:put('6. Proactive Defence','Rootkit Check','Warning','rkhunter warning lines: '+str(len(warn))+'; '+warn[-1][:150]+'; possible false positives require review')
    elif re.search(r'(?i)scan.*(?:complete|finished)|system checks summary',rkh):
        try: age=(time.time()-os.stat(rkhpath).st_mtime)/86400
        except OSError: age=999
        put('6. Proactive Defence','Rootkit Check','Good' if age<=a.report_max_age_days else 'Warning','rkhunter completion summary without recognized warning lines; age={:.1f}d; bounded tail; not independent rootkit proof'.format(age))
    elif not rkh:put('6. Proactive Defence','Rootkit Check','Review','No readable completed rkhunter result; audit did not run rootkit scans')
    chk=read('/root/scripts/chkrootkit-report.txt',True)
    if not rkh and chk:
        threats=[line for line in chk.splitlines() if re.search(r'(?i)\bINFECTED\b|\bVulnerable\b',line) and not re.search(r'(?i)not infected|not vulnerable',line)]
        put('6. Proactive Defence','Rootkit Check','Warning' if threats else 'Review','Existing chkrootkit report: '+('suspicious findings: '+' | '.join(threats[:3]) if threats else 'No explicit clean completion established; review raw report')+'; /root/scripts/chkrootkit-report.txt')
    php_security(packages);network_checks(a,system);health_container(system)
    webinstalled=bool(re.search(r'(?m)^(?:ea-)?(?:httpd|apache|nginx|lshttpd|litespeed|lsws)(?:\s|[-0-9])',packages,re.I))
    webactive=bool(re.search(r'(?:httpd|apache2|nginx|lshttpd|lsws)\.service',units))
    if not webactive:
        put('3. Server Health','HTTP Uptime','Warning' if webinstalled else 'Not applicable' if packages else 'Unknown','Web-server package present but no running known service detected' if webinstalled else 'No supported local web-server package/running service detected; custom/containerized services may exist')
    if not shutil.which('exim'):
        if shutil.which('postqueue'):
            q=jrun('postqueue','-j') # JSON-lines fallback is counted separately
            rawq=run('postqueue','-j');count=sum(1 for l in rawq.splitlines() if l.strip().startswith('{'))
            if RUN_META.get(('postqueue','-j'))==0:put('3. Server Health','Email Queue','Warning' if count>100 else 'Good','Postfix queued messages='+str(count))
        elif not any(shutil.which(x) for x in ['postfix','sendmail','postqueue']):put('3. Server Health','Email Queue','Not applicable','No supported local mail queue tool detected')
    # Root account lock status changes the password-age interpretation.
    entry=next((l.split(':') for l in read('/etc/shadow').splitlines() if l.startswith('root:')),[])
    if len(entry)>2:
        locked=entry[1].startswith(('!','*'))
        try:age=int(time.time()/86400)-int(entry[2])
        except ValueError:age=None
        if locked:put('6. Proactive Defence','Root password health','Not applicable','Root password locked; SSH root/key policy checked separately; password age alone is not a risk score')
        elif age is not None:put('6. Proactive Defence','Root password health','Warning' if age>180 else 'Good','Root password age='+str(age)+'d; audit threshold=180d; align with organizational policy; hash never printed')
    put('6. Proactive Defence','Reboot Procedure','Review','Recovery/reboot access needs documentation; '+system['System Type']+' detected; audit performs no reboot')
    extra_backup_logs(a.backup_log,a.backup_max_age_days);backup_schedule_fallback(panel)
    # Separate EA upstream EOL from alt-PHP vendor extension; report compact versions, not 45 random extension packages.
    ea=sorted(set(re.findall(r'(?m)^ea-php(\d{2})(?:\s|[-])',packages)))
    alt=sorted(set(re.findall(r'(?m)^alt-php(\d{2})(?:\s|[-])',packages)))
    generic=sorted(set(re.findall(r'(?m)^php(?:\d[\d.]*)?(?:\s|[-])\S*\s+(?:\d+:)?(\d+\.\d+)',packages)))
    today=dt.date.today();ends={'82':dt.date(2026,12,31),'83':dt.date(2027,12,31),'84':dt.date(2028,12,31),'85':dt.date(2029,12,31)}
    eol=lambda x:int(x)<=81 or (x in ends and today>ends[x])
    bad=[x for x in ea if eol(x)]
    put('5. Software Life Time','Software Stack','Warning' if bad else 'Review' if ea or alt or generic else 'Review','EA PHP upstream-EOL families='+(','.join(bad) or 'none detected')+'; EA installed='+','.join(ea)+'; alt-PHP installed='+','.join(alt)+' (CloudLinux extended coverage requires entitlement verification; not automatically unsupported); system PHP='+','.join(generic)+'; database/web/crypto distro support follows supported OS repositories/backports, custom installs need review')

if __name__=='__main__': main()

#!/usr/bin/env python3
"""TargetScan: discover -> detect services -> enumerate -> PDF/JSON."""
import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

# Explicit, bounded inventory scripts; no brute force or exploit categories.
RULES = {
 'http': ['http-title','http-headers','http-server-header'],
 'ftp': ['ftp-syst','ftp-anon'],
 'ssh': ['ssh-hostkey','ssh2-enum-algos'],
 'smb': ['smb-protocols','smb2-security-mode','smb-os-discovery'],
 'dns': ['dns-recursion'],
 'smtp': ['smtp-commands'],
 'mysql': ['mysql-info'],
 'rdp': ['rdp-ntlm-info'],
 'tls': ['ssl-cert'],
}


def normalize(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',value):
        raise ValueError('Enter one IP or hostname only; no URL, CIDR, ports or options.')
    if any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in value.split('.')):
        raise ValueError('Invalid hostname.')
    return value.lower()


def resolve(target, override=None):
    addresses = sorted({i[4][0] for i in socket.getaddrinfo(target,None,type=socket.SOCK_STREAM)})
    if override:
        override = str(ipaddress.ip_address(override))
        if override not in addresses: raise ValueError('--address must be one of the resolved addresses.')
        return override, addresses
    if not addresses: raise ValueError('No address resolved.')
    return next((a for a in addresses if ':' not in a),addresses[0]), addresses


def parse_xml(path):
    root = ET.parse(path).getroot()
    hosts=[]
    for h in root.findall('host'):
        ports=[]
        for p in h.findall('ports/port'):
            svc=p.find('service'); state=p.find('state')
            ports.append({'port':int(p.get('portid')),'protocol':p.get('protocol'),
              'state':state.get('state') if state is not None else 'unknown',
              'reason':state.get('reason') if state is not None else '',
              'service':dict(svc.attrib) if svc is not None else {},
              'scripts':[{'id':s.get('id'),'output':s.get('output','')} for s in p.findall('script')]})
        status=h.find('status')
        hosts.append({'status':status.get('state') if status is not None else 'unknown',
          'reason':status.get('reason','') if status is not None else '',
          'addresses':[a.get('addr') for a in h.findall('address')], 'ports':ports,
          'scripts':[{'id':s.get('id'),'output':s.get('output','')} for s in h.findall('hostscript/script')],
          'os':[o.attrib for o in h.findall('os/osmatch')]})
    finished=root.find('runstats/finished')
    return {'hosts':hosts,'finished':dict(finished.attrib) if finished is not None else {},
            'summary_states':[s.attrib for s in root.findall('host/ports/extraports')]}


def select_scripts(port):
    service=port['service']; name=service.get('name','').lower(); number=port['port']; result=[]
    if 'http' in name: result += RULES['http']
    if name=='ftp': result += RULES['ftp']
    if name=='ssh': result += RULES['ssh']
    if name in ('microsoft-ds','netbios-ssn') or number in (139,445): result += RULES['smb']
    if name in ('domain','dns'): result += RULES['dns']
    if name in ('smtp','submission','smtps'): result += RULES['smtp']
    if name=='mysql': result += RULES['mysql']
    if name in ('ms-wbt-server','rdp'): result += RULES['rdp']
    if service.get('tunnel')=='ssl' or name=='https': result += RULES['tls']
    return sorted(set(result))


def run_stage(label, options, address, out, timeout):
    xml=out/(label+'.xml')
    cmd=['nmap','-n']+(['-6'] if ':' in address else [])+options+['-oX',str(xml),address]
    print('\n['+label+'] '+ ' '.join(cmd),flush=True)
    stage={'name':label,'command':cmd,'status':'unknown','hosts':[]}
    try:
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
        (out/(label+'.log')).write_text(result.stdout+'\n'+result.stderr)
        stage['status']='completed' if result.returncode==0 else 'failed'
        stage['error']=result.stderr[-2000:]
    except subprocess.TimeoutExpired as e:
        stage['status']='timeout'; stage['error']='Stage timed out; incomplete results.'
        (out/(label+'.log')).write_text(str(e))
    if xml.exists():
        try: stage.update(parse_xml(xml))
        except ET.ParseError: stage['error']='Incomplete XML; consult stage log.'
    if stage.get('finished',{}).get('exit')=='error': stage['status']='failed'
    return stage


def findings(stages):
    result=[]; seen=set()
    for stage in stages:
        for host in stage.get('hosts',[]):
            for port in host['ports']:
                for s in port['scripts']+host['scripts']:
                    level=title=fix=None
                    if s['id']=='ftp-anon' and 'Anonymous FTP login allowed' in s['output']:
                        level='Medium'; title='Anonymous FTP login accepted'; fix='Confirm intended public access; restrict anonymous permissions and disable it if unnecessary.'
                    if s['id']=='smb-protocols' and 'NT LM 0.12' in s['output']:
                        level='High'; title='SMBv1 supported'; fix='Disable SMBv1 after checking client compatibility; use supported SMB versions.'
                    if s['id']=='smb2-security-mode' and 'enabled but not required' in s['output'].lower():
                        level='Medium'; title='SMB signing not required'; fix='Evaluate enforcing SMB signing on clients and servers.'
                    if s['id']=='dns-recursion' and 'Recursion appears to be enabled' in s['output']:
                        level='Low'; title='DNS recursion available to scanner'; fix='Check whether this client should have recursion access; restrict resolver ACLs as appropriate.'
                    key=(title,port['port'],port['protocol'])
                    if title and key not in seen:
                        seen.add(key); result.append({'severity':level,'title':title,'endpoint':f"{port['port']}/{port['protocol']}",'evidence':s['output'],'recommendation':fix})
    return result


def write_report(data, path):
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from xml.sax.saxutils import escape
    styles=getSampleStyleSheet(); styles['BodyText'].fontSize=9; styles['BodyText'].leading=13; styles['BodyText'].wordWrap='CJK'
    def p(s,style='BodyText'): return Paragraph(escape(str(s)).replace('\n','<br/>'),styles[style])
    story=[p('TARGETSCAN','Title'),p('Network assessment and service enumeration','Heading2'),Spacer(1,12),p(data['target'],'Heading1'),p('Pinned address: '+data['address']),p(data['time']),Spacer(1,15),p('Assessment summary','Heading2'),p('Workflow: discovery, port scan, version detection, then enumeration of discovered services.'),p('Scope: one pinned IP. Website results may describe a CDN or shared frontend; origin servers are not discovered. Versions and OS fingerprints are estimates, not confirmed vulnerabilities.')]
    table=Table([[p('Stage'),p('Status'),p('Hosts recorded')]]+[[p(s['name']),p(s['status']),p(len(s.get('hosts',[])))] for s in data['stages']],colWidths=[230,120,120])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dceaf1')),('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    story += [Spacer(1,12),table,Spacer(1,12),p(f"{len(data['findings'])} rule-based findings. No numerical security score is assigned."),p('Failed, timed-out and unanswered checks are unknown. An empty finding list is not evidence that a target is secure.'),PageBreak(),p('Findings and next steps','Heading1')]
    for f in data['findings']:
        story += [p(f['severity']+' | '+f['title'],'Heading2'),p(f['endpoint']),p(f['evidence']),p('Recommendation: '+f['recommendation']),Spacer(1,12)]
    if not data['findings']: story.append(p('No supported rule produced a finding. Review discovered services and coverage below.'))
    story += [p('Scan scope','Heading2'),p(json.dumps(data['options'],indent=2)),p('All resolved addresses (only the pinned address was scanned): '+', '.join(data['resolved'])),PageBreak(),p('Service inventory and evidence','Heading1')]
    for s in data['stages']:
        story += [p(s['name']+' | '+s['status'],'Heading2')]
        if s.get('error'): story.append(p(s['error']))
        if not s.get('hosts'): story.append(p('No host results recorded.'))
        for h in s.get('hosts',[]):
            story += [p('Host status: '+h['status']+'; reason: '+h['reason'])]
            for port in h['ports']:
                svc=port['service']
                story += [p(f"{port['port']}/{port['protocol']} | {port['state']} | {svc.get('name','unknown')}",'Heading3'),p(' '.join(svc.get(k,'') for k in ['product','version','extrainfo']))]
                for script in port['scripts']: story += [p(script['id'],'Heading4'),p(script['output'][:6000])]
            for script in h['scripts']: story += [p(script['id'],'Heading3'),p(script['output'][:6000])]
            if h['os']: story.append(p('OS guesses: '+json.dumps(h['os'])))
    story += [p('Interpretation','Heading2'),p('open: listener detected. filtered: probes blocked or unanswered. open|filtered: ambiguous, especially UDP. NSE scripts may omit output when inapplicable or inconclusive; absent output is not a pass. TCP coverage is selected ports only unless --all-ports is used. UDP coverage is only the selected top UDP ports. PDF script excerpts stop at 6000 characters; JSON and XML retain complete script outputs.')]
    def footer(c,d):
        c.setFont('Helvetica',8); c.drawString(36,22,'TargetScan | Authorized target assessment'); c.drawRightString(559,22,str(d.page))
    SimpleDocTemplate(str(path),leftMargin=36,rightMargin=36,topMargin=40,bottomMargin=40).build(story,onFirstPage=footer,onLaterPages=footer)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('target',nargs='?',help='Single IP or hostname, without https://')
    ap.add_argument('--address',help='Select one resolved IP for a multi-address hostname')
    group=ap.add_mutually_exclusive_group(); group.add_argument('--all-ports',action='store_true'); group.add_argument('--ports',help='TCP ports, e.g. 22,80,443 or 1-1024')
    ap.add_argument('--udp',action='store_true',help='Scan top 20 UDP ports (root required)')
    ap.add_argument('--skip-discovery',action='store_true',help='Continue if host discovery is blocked')
    ap.add_argument('--os',action='store_true',help='Attempt OS fingerprinting (root required)')
    ap.add_argument('--timeout',type=int,default=1800,help='Maximum seconds per stage (default 1800)')
    ap.add_argument('--output',default='reports'); ap.add_argument('--demo',action='store_true')
    args=ap.parse_args()
    if args.timeout<30: ap.error('--timeout must be at least 30 seconds')
    if args.ports and (not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*',args.ports) or any(not 1<=int(n)<=65535 for n in re.findall(r'\d+',args.ports))): ap.error('Invalid TCP port list')
    if args.ports:
        for item in args.ports.split(','):
            pair=item.split('-')
            if len(pair)==2 and int(pair[0])>int(pair[1]): ap.error('Port ranges must ascend')
    out=Path(args.output)/datetime.now().strftime('%Y%m%d-%H%M%S-%f'); os.umask(0o077); out.mkdir(parents=True)
    if args.demo:
        data=json.loads((Path(__file__).parent/'examples/demo.json').read_text())
    else:
        if not shutil.which('nmap'): ap.error('Nmap missing: sudo apt install nmap')
        if (args.udp or args.os) and os.geteuid()!=0: ap.error('--udp and --os require sudo')
        try:
            target=normalize(args.target or input('Target IP or hostname: ')); address,addresses=resolve(target,args.address)
        except (ValueError,OSError) as e: ap.error(str(e))
        data={'target':target,'address':address,'resolved':addresses,'time':datetime.now().astimezone().isoformat(),'options':vars(args),'stages':[],'findings':[]}
        def stage(label,opts):
            s=run_stage(label,opts,address,out,args.timeout); data['stages'].append(s)
            (out/'report.json').write_text(json.dumps(data,indent=2)); return s
        discovery=stage('01-discovery',['-sn'])
        alive=any(h['status']=='up' for h in discovery['hosts'])
        if alive or args.skip_discovery:
            scope=['-p-'] if args.all_ports else ['-p',args.ports] if args.ports else ['--top-ports','1000']
            tcp=stage('02-tcp',['-Pn','-sT','-T3','--reason']+scope)
            scans=[tcp]
            if args.udp: scans.append(stage('03-udp',['-Pn','-sU','--top-ports','20','-T3','--reason']))
            for scan in scans:
                proto='udp' if scan is not tcp else 'tcp'
                candidates=sorted({p['port'] for h in scan['hosts'] for p in h['ports'] if p['state'] in ('open','open|filtered')})
                if not candidates: continue
                opts=['-Pn','-sU' if proto=='udp' else '-sT','-sV','--version-light','-p',','.join(map(str,candidates))]
                if args.os and proto=='tcp': opts+=['-O','--osscan-limit']
                detected=stage('04-services-'+proto,opts)
                for host in detected['hosts']:
                    for port in host['ports']:
                        if port['state']!='open': continue
                        scripts=select_scripts(port)
                        if not scripts: continue
                        options=['-Pn','-sU' if proto=='udp' else '-sT','-sV','--version-light','-p',str(port['port']),'--script',','.join(scripts),'--script-timeout','45s']
                        try: ipaddress.ip_address(target)
                        except ValueError: options += ['--script-args','http.host='+target+',tls.servername='+target]
                        stage(f"05-enum-{proto}-{port['port']}",options)
        else: print('No discovery response. Use --skip-discovery if probes are blocked; no port scan performed.')
        data['findings']=findings(data['stages'])
    (out/'report.json').write_text(json.dumps(data,indent=2))
    write_report(data,out/'report.pdf')
    print('\nReport: '+str((out/'report.pdf').resolve()))
    print('JSON/XML evidence: '+str(out.resolve()))

if __name__=='__main__':
    try: main()
    except KeyboardInterrupt: print('\nInterrupted. Completed stage evidence remains in output directory.'); sys.exit(130)

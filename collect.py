"""Collect public URI subscriptions; upstream text is data and is never executed."""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import html.parser
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward provider credentials to another host or dashboard login.
        return None

def github_source_url(value):
    parsed=urllib.parse.urlsplit(value)
    if parsed.scheme!='https' or parsed.username or parsed.password or parsed.port or parsed.query: raise ValueError('source')
    parts=parsed.path.strip('/').split('/')
    if len(parts)==2 and parts[-1].endswith('.git'): parts[-1]=parts[-1][:-4]
    if parsed.hostname=='openproxylist.com' and parsed.path.rstrip('/')=='/v2ray': return 'https://openproxylist.com/v2ray'
    if parsed.hostname=='github.com' and len(parts)==2 and all(re.fullmatch(r'[A-Za-z0-9_.-]+',part) and part not in ('.','..') for part in parts):
        return 'https://github.com/'+'/'.join(parts)
    if parsed.hostname=='t.me':
        if parts[0]=='s': parts=parts[1:]
        if len(parts)!=1 or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{3,31}',parts[0]): raise ValueError('channel')
        return 'https://t.me/s/'+parts[0]
    if parsed.hostname=='github.com' and len(parts)>=5 and parts[2]=='blob':
        parts.pop(2)
    elif parsed.hostname!='raw.githubusercontent.com' or len(parts)<4:
        raise ValueError('source')
    if any(not part or part in ('.','..') for part in parts): raise ValueError('source')
    return 'https://raw.githubusercontent.com/'+'/'.join(parts)

def parse_github_configs(content):
    text=content.decode('utf-8-sig').strip()
    if '://' not in text:
        try: text=base64.b64decode(text+'='*(-len(text)%4),altchars=b'-_',validate=False).decode('utf-8-sig')
        except (ValueError,UnicodeError): return []
    result=[]
    for line in text.splitlines():
        line=line.strip()
        if len(line)>16384 or any(c.isspace() for c in line): continue
        if re.fullmatch(r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic)://[^<>"\s]+',line): result.append(line)
    return result

class TelegramConfigParser(html.parser.HTMLParser):
    """Only read public post bodies; ignore page scripts, links and navigation."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth=0;self.parts=[]

    def handle_starttag(self,tag,attrs):
        if tag=='div':
            if self.depth: self.depth+=1
            elif 'tgme_widget_message_text' in dict(attrs).get('class','').split(): self.depth=1
        if self.depth and tag in ('br','p','pre','code'): self.parts.append('\n')

    def handle_endtag(self,tag):
        if self.depth and tag=='div':
            self.depth-=1
            if not self.depth: self.parts.append('\n')
        elif self.depth and tag in ('p','pre','code'): self.parts.append('\n')

    def handle_data(self,data):
        if self.depth: self.parts.append(data)

def fetch_public_config(url):
    opener=urllib.request.build_opener(NoRedirect)
    original_host=urllib.parse.urlsplit(url).hostname
    for attempt in range(4):
        try:
            with opener.open(urllib.request.Request(url,headers=fetch_headers(url)),timeout=15) as response:
                content=response.read(2*1024*1024+1)
            if len(content)>2*1024*1024: raise ValueError('size')
            return content
        except urllib.error.HTTPError as error:
            location=error.headers.get('Location','')
            status=error.code
            error.close()
            target=urllib.parse.urlsplit(urllib.parse.urljoin(url,location))
            # Repository renames may redirect within GitHub's API; never follow off-host URLs.
            if status not in (301,302,307,308) or not location or attempt==3 or target.scheme!='https' or target.hostname!=original_host or target.username or target.password or target.port not in (None,443): raise
            url=target.geturl()
    raise ValueError('redirect')

def collect_config_source(source,cancel=None,max_files=200):
    if cancel is not None and cancel.is_set(): return [],True
    url=github_source_url(source)
    partial=False
    if url.startswith('https://github.com/'):
        repo=url.removeprefix('https://github.com/')
        tree=json.loads(fetch_public_config('https://api.github.com/repos/'+repo+'/git/trees/HEAD?recursive=1'))
        partial=bool(tree.get('truncated'))
        paths=[item['path'] for item in tree.get('tree',[]) if item.get('type')=='blob' and item.get('mode')!='120000' and item.get('size',0)<=2*1024*1024
               and not item['path'].startswith('.') and Path(item['path']).suffix.lower() in ('','.txt','.conf','.base64','.b64')
               and not any(word in item['path'].lower() for word in ('readme','license','requirements','clash','mihomo'))]
        paths.sort(key=lambda path:(0 if any(word in path.lower() for word in ('all','mix','base64','merged','config.txt','sub.txt')) else 1,len(path),path))
        partial=partial or len(paths)>max_files
        urls=['https://raw.githubusercontent.com/'+repo+'/HEAD/'+urllib.parse.quote(path,safe='/') for path in paths[:max_files]]
    elif url=='https://openproxylist.com/v2ray': urls=['https://openproxylist.com/v2ray/rawlist/text']
    else: urls=[url]
    configs=[];failed=0
    for item in urls:
        if cancel is not None and cancel.is_set(): return configs,True
        try:
            content=fetch_public_config(item)
            if item.startswith('https://t.me/s/'):
                parser=TelegramConfigParser();parser.feed(content.decode('utf-8'))
                candidates=re.findall(r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic)://[^<>"\s]+',''.join(parser.parts))
                content='\n'.join(candidates).encode('utf-8')
            configs.extend(parse_github_configs(content)[:50000-len(configs)])
            if len(configs)>=50000: return configs,True
        except (OSError,ValueError,UnicodeError): failed+=1
    return configs,partial or bool(failed)


def fetch_headers(url):
    headers={'User-Agent':'MahXray-ConfigCollector','Accept-Encoding':'identity'}
    token=os.getenv('GITHUB_TOKEN','')
    if token and urllib.parse.urlsplit(url).hostname=='api.github.com':
        headers['Authorization']='Bearer '+token
    return headers


def config_identity(value):
    value=value.split('#',1)[0]
    if value.startswith('vmess://'):
        encoded=value[8:]
        try:
            data=json.loads(base64.b64decode(encoded+'='*(-len(encoded)%4),altchars=b'-_'))
            if isinstance(data,dict):
                data.pop('ps',None)
                return 'vmess:'+json.dumps(data,sort_keys=True,separators=(',',':'))
        except (ValueError,UnicodeError): pass
    return value


def atomic_write(path,text):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    descriptor,temporary=tempfile.mkstemp(prefix='.collect-',dir=path.parent)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8',newline='\n') as stream: stream.write(text)
        os.replace(temporary,path)
    finally: Path(temporary).unlink(missing_ok=True)


def publish(root,sources,results):
    root=Path(root)
    unique={};reports=[];limited=False;size=0
    now=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    for source,result in zip(sources,results):
        cache=Path('data/sources')/(hashlib.sha256(source.encode()).hexdigest()[:16]+'.txt')
        found=result.get('configs',[])
        retained=False
        if not found and (root/cache).is_file():
            found=parse_github_configs((root/cache).read_bytes());retained=bool(found)
        elif found:
            found=list(dict.fromkeys(found))
            atomic_write(root/cache,'\n'.join(found)+'\n')
        for config in found:
            key=config_identity(config)
            if key in unique: continue
            length=len(config.encode('utf-8'))+1
            if len(unique)>=200000 or size+length>32*1024*1024:
                limited=True;continue
            unique[key]=config;size+=length
        report=dict(url=source,count=len(found),retained_previous=retained,
                    status='failed' if result.get('error') or not result.get('configs') else 'partial' if result.get('partial') else 'ok')
        if result.get('error'): report['error']=result['error']
        if found: report['file']=cache.as_posix()
        reports.append(report)
    if unique:
        content='\n'.join(unique.values())+'\n'
        atomic_write(root/'configs.txt',content)
        atomic_write(root/'base64.txt',base64.b64encode(content.encode()).decode()+'\n')
    else:
        # A total outage must not replace a previously published working snapshot.
        if (root/'configs.txt').is_file():
            unique={config_identity(config):config for config in parse_github_configs((root/'configs.txt').read_bytes())}
    status=dict(updated_at=now,unique_configs=len(unique),source_count=len(sources),
                successful_sources=sum(row['status']=='ok' for row in reports),
                export_limited=limited,sources=reports,
                limits=dict(files_per_repository=200,bytes_per_response=2*1024*1024,configs_per_source=50000,
                            configs_total=200000,export_bytes=32*1024*1024))
    atomic_write(root/'status.json',json.dumps(status,ensure_ascii=False,indent=2)+'\n')
    return status


def run_source(source):
    try:
        configs,partial=collect_config_source(source)
        return dict(configs=configs,partial=partial)
    except urllib.error.HTTPError as error:
        code=error.code;error.close()
        return dict(configs=[],error='HTTP '+str(code))
    except Exception as error:
        # Only error types are published, never upstream bodies or authorization headers.
        return dict(configs=[],error=type(error).__name__)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
    args=parser.parse_args()
    sources=list(dict.fromkeys(github_source_url(value) for value in json.loads((args.root/'sources.json').read_text(encoding='utf-8'))))
    if not sources or len(sources)>100: raise ValueError('Expected 1 to 100 public sources')
    results=[None]*len(sources)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending={pool.submit(run_source,source):index for index,source in enumerate(sources)}
        for future in concurrent.futures.as_completed(pending):
            index=pending[future];source=sources[index];result=future.result()
            results[index]=result
            print(source+': '+str(len(result.get('configs',[])))+' configs'+(' (partial)' if result.get('partial') else '')+(' '+result['error'] if result.get('error') else ''),flush=True)
    status=publish(args.root,sources,results)
    print('Published '+str(status['unique_configs'])+' unique configs',flush=True)
    return 0 if status['unique_configs'] else 1


if __name__=='__main__':
    raise SystemExit(main())

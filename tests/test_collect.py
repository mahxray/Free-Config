import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock, Mock

import collect


class CollectorTests(unittest.TestCase):
    def test_sources_are_normalized_and_untrusted_hosts_rejected(self):
        self.assertEqual(collect.github_source_url('https://github.com/a/b.git'),'https://github.com/a/b')
        self.assertEqual(collect.github_source_url('https://github.com/a/b/blob/main/sub.txt'),'https://raw.githubusercontent.com/a/b/main/sub.txt')
        self.assertEqual(collect.github_source_url('https://t.me/v2ray_free_config_iran'),'https://t.me/s/v2ray_free_config_iran')
        self.assertEqual(collect.github_source_url('https://raw.githubusercontent.com/a/b/main/sub.txt#name'),'https://raw.githubusercontent.com/a/b/main/sub.txt')
        for url in ('http://github.com/a/b','https://evil.test/a','https://github.com@127.0.0.1/a/b','https://t.me/+private'):
            with self.subTest(url=url), self.assertRaises(ValueError): collect.github_source_url(url)

    def test_config_plain_base64_and_supported_protocols(self):
        text='vless://id@example.com:443#label\ntrojan://pw@example.com:443\ninvalid\n'
        expected=text.splitlines()[:2]
        self.assertEqual(collect.parse_github_configs(text.encode()),expected)
        self.assertEqual(collect.parse_github_configs(base64.b64encode(text.encode())),expected)
        self.assertEqual(collect.parse_github_configs(b'<script>bad</script>'),[])

    def test_telegram_only_extracts_public_post_bodies(self):
        html='<script>vless://bad</script><div class="tgme_widget_message_text js-message_text"><code>vless://id@example.com:443?a=1&amp;b=2</code><code>trojan://pw@example.com:443</code></div>'
        with patch.object(collect,'fetch_public_config',return_value=html.encode()):
            found,partial=collect.collect_config_source('https://t.me/s/v2ray_free_config_iran')
        self.assertEqual(found,['vless://id@example.com:443?a=1&b=2','trojan://pw@example.com:443'])
        self.assertFalse(partial)

    def test_repository_discovery_limits_files_and_ignores_source_code(self):
        tree={'tree':[{'type':'blob','path':path,'size':100} for path in ('all.txt','other.txt','script.py','config.yaml')]}
        def fetch(url):
            return json.dumps(tree).encode() if 'api.github.com' in url else b'vless://id@example.com:443'
        with patch.object(collect,'fetch_public_config',side_effect=fetch) as fetcher:
            found,partial=collect.collect_config_source('https://github.com/a/b',max_files=1)
        self.assertEqual(len(found),1)
        self.assertTrue(partial)
        self.assertEqual(fetcher.call_count,2)

    def test_api_token_never_goes_to_raw_files_or_telegram(self):
        with patch.dict(collect.os.environ,{'GITHUB_TOKEN':'test-secret'}):
            self.assertEqual(collect.fetch_headers('https://api.github.com/repos/a/b')['Authorization'],'Bearer test-secret')
            for url in ('https://raw.githubusercontent.com/a/b/main/sub.txt','https://t.me/s/channel','https://openproxylist.com/v2ray'):
                self.assertNotIn('Authorization',collect.fetch_headers(url))

    def test_cross_host_redirect_is_not_followed(self):
        error=collect.urllib.error.HTTPError('https://api.github.com/repos/a/b',301,'Moved',{'Location':'https://127.0.0.1/private'},None)
        opener=Mock();opener.open.side_effect=error
        with patch.object(collect.urllib.request,'build_opener',return_value=opener):
            with self.assertRaises(collect.urllib.error.HTTPError): collect.fetch_public_config('https://api.github.com/repos/a/b')
        self.assertEqual(opener.open.call_count,1)

    def test_vmess_display_name_is_not_identity(self):
        def uri(name):
            return 'vmess://'+base64.b64encode(json.dumps({'add':'example.com','id':'test','ps':name}).encode()).decode()
        self.assertEqual(collect.config_identity(uri('one')),collect.config_identity(uri('two')))

    def test_publish_deduplicates_and_preserves_failed_source_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            sources=['https://github.com/a/b','https://github.com/c/d']
            first=collect.publish(directory,sources,[{'configs':['vless://id@example.com:443#one']},{'configs':['trojan://pw@example.com:443']}])
            self.assertEqual(first['unique_configs'],2)
            second=collect.publish(directory,sources,[{'configs':['vless://id@example.com:443#two','trojan://pw@example.com:443']},{'configs':[],'error':'HTTP 404'}])
            self.assertEqual(second['unique_configs'],2)
            self.assertTrue(second['sources'][1]['retained_previous'])
            content=Path(directory,'configs.txt').read_bytes()
            self.assertEqual(base64.b64decode(Path(directory,'base64.txt').read_bytes()),content)
            self.assertEqual(json.loads(Path(directory,'status.json').read_text(encoding='utf-8'))['sources'][1]['error'],'HTTP 404')

    def test_total_outage_preserves_published_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'configs.txt').write_text('vless://id@example.com:443\n',encoding='utf-8')
            status=collect.publish(directory,['https://github.com/a/b'],[{'configs':[],'error':'HTTP 404'}])
            self.assertEqual(status['unique_configs'],1)
            self.assertEqual(Path(directory,'configs.txt').read_text(),'vless://id@example.com:443\n')

    def test_partial_and_unavailable_sources_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            status=collect.publish(directory,['https://github.com/a/b','https://github.com/c/d'],[{'configs':['vless://id@example.com:443'],'partial':True},{'configs':[],'error':'HTTP 404'}])
            self.assertEqual(status['source_count'],2)
            self.assertEqual(status['sources'][0]['status'],'partial')
            self.assertEqual(status['sources'][1]['status'],'failed')
            self.assertFalse(status['sources'][1]['retained_previous'])

    def test_empty_first_run_does_not_publish_an_empty_subscription(self):
        with tempfile.TemporaryDirectory() as directory:
            status=collect.publish(directory,['https://github.com/a/b'],[{'configs':[],'error':'HTTP 404'}])
            self.assertEqual(status['unique_configs'],0)
            self.assertFalse(Path(directory,'configs.txt').exists())
            self.assertFalse(Path(directory,'base64.txt').exists())

    def test_default_sources_are_unique_and_valid(self):
        sources=json.loads(Path('sources.json').read_text(encoding='utf-8'))
        self.assertEqual(len(sources),28)
        self.assertEqual(len(sources),len(set(sources)))
        for url in sources: self.assertEqual(url,collect.github_source_url(url))


if __name__=='__main__': unittest.main()

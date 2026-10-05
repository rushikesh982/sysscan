import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from targetscan import normalize,resolve,parse_xml,select_scripts,findings,run_stage

class Tests(unittest.TestCase):
 def test_input_rejects_options_urls_and_ranges(self):
  for s in ['-sV','https://site.example','192.168.1.0/24','a;touch x','a,b','bad..host']:
   with self.assertRaises(ValueError): normalize(s)
  self.assertEqual(normalize('2001:db8::1'),'2001:db8::1')
 def test_address_pinning(self):
  with patch('socket.getaddrinfo',return_value=[(None,None,None,None,('192.0.2.1',0)),(None,None,None,None,('192.0.2.2',0))]):
   self.assertEqual(resolve('lab.example','192.0.2.2')[0],'192.0.2.2')
   with self.assertRaises(ValueError): resolve('lab.example','192.0.2.3')
 def test_enumeration_selected_by_service(self):
  self.assertEqual(select_scripts({'port':8080,'service':{'name':'http','tunnel':'ssl'}}),['http-headers','http-server-header','http-title','ssl-cert'])
  self.assertEqual(select_scripts({'port':1234,'service':{'name':'unknown'}}),[])
 def test_xml_preserves_udp_ambiguity(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'x.xml';p.write_text('<nmaprun><host><status state="up"/><ports><port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port></ports></host></nmaprun>')
   self.assertEqual(parse_xml(p)['hosts'][0]['ports'][0]['state'],'open|filtered')
 def test_version_alone_not_vulnerability(self):
  host={'ports':[{'port':21,'protocol':'tcp','service':{'version':'2.3.4'},'scripts':[]}],'scripts':[]}
  self.assertEqual(findings([{'hosts':[host]}]),[])
 def test_anonymous_login_finding(self):
  host={'ports':[{'port':21,'protocol':'tcp','scripts':[{'id':'ftp-anon','output':'Anonymous FTP login allowed (FTP code 230)'}]}],'scripts':[]}
  self.assertEqual(findings([{'hosts':[host]}])[0]['severity'],'Medium')
 def test_command_is_argument_list(self):
  with tempfile.TemporaryDirectory() as t,patch('subprocess.run') as run:
   run.return_value.returncode=1;run.return_value.stdout='';run.return_value.stderr='missing'
   self.assertEqual(run_stage('test',['-sn'],'192.0.2.1',Path(t),30)['status'],'failed')
   self.assertIsInstance(run.call_args.args[0],list)
if __name__=='__main__': unittest.main()

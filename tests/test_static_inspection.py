"""Real static buttons, bounded string evidence and PE/ELF header semantics."""
from pathlib import Path
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_staged_analysis import pe_fixture
from rea_analysis import StaticAnalysis
from rea_static_tools import StaticInspectionWorker
from rea_mcp import McpCancelled

class StaticInspection(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.target=self.root/'fixture.exe'
        pe_fixture(self.target)
    def tearDown(self):self.tmp.cleanup()
    def test_extract_strings_button_uses_working_bounded_service(self):
        self.target.write_bytes(b'\x00KnownPlainText\x00'+ 'Türkçe'.encode() +b'\x00\x00'+ 'WideLittle'.encode('utf-16-le')+b'\x00\x00'+ 'WideBig'.encode('utf-16-be'))
        before=self.target.read_bytes();r=StaticInspectionWorker('strings',str(self.target)).analyze()
        self.assertTrue(any(s['text']=='KnownPlainText' and s['offset']==1 for s in r['strings']))
        self.assertTrue(any(s['text']=='Türkçe' for s in r['strings']))
        self.assertTrue(any(s['text']=='WideLittle' and s['encoding'].startswith('UTF-16LE') for s in r['strings']))
        self.assertTrue(any(s['text']=='WideBig' and s['encoding'].startswith('UTF-16BE') for s in r['strings']))
        self.assertEqual(before,self.target.read_bytes());self.assertFalse(r['partial'])
    def test_string_crossing_a_chunk_boundary_is_retained_once(self):
        self.target.write_bytes(b'\x00'*65530+b'CrossBoundaryEvidence'+b'\x00'*20)
        r=StaticAnalysis(self.target).strings()
        matches=[s for s in r['strings'] if s['text']=='CrossBoundaryEvidence']
        self.assertEqual(len(matches),1);self.assertEqual(matches[0]['offset'],65530)
    def test_large_string_output_keeps_partial_results_instead_of_failing(self):
        self.target.write_bytes(b'A'*(4*1024**2))
        r=StaticAnalysis(self.target).strings(max_rows=20,max_text_bytes=4096)
        self.assertTrue(r['partial']);self.assertTrue(r['strings']);self.assertLess(r['scanned_bytes'],r['file_bytes'])
        self.assertLessEqual(sum(len(s['text'].encode()) for s in r['strings']),4096)
    def test_pe_flags_are_observations_and_never_signature_verification(self):
        raw=bytearray(self.target.read_bytes())
        struct.pack_into('<H',raw,0x98+70,0x40|0x100|0x4000|0x20)
        struct.pack_into('<I',raw,0x98+92,16)
        struct.pack_into('<II',raw,0x98+96+4*8,512,16)
        self.target.write_bytes(raw)
        r=StaticInspectionWorker('security_audit',self.target).analyze();o=r['observations']
        self.assertEqual(r['format'],'PE');self.assertTrue(o['dynamic_base'] and o['nx_compatible'] and o['guard_cf'])
        self.assertTrue(o['certificate_table_declared'] and o['certificate_table_in_file']);self.assertFalse(o['signature_verified'])
        self.assertIn('İmza doğrulanmadı',r['report'])
    def test_pe64_header_uses_the_64_bit_image_base(self):
        raw=bytearray(self.target.read_bytes());struct.pack_into('<H',raw,0x84,0x8664)
        struct.pack_into('<H',raw,0x98,0x20b);struct.pack_into('<Q',raw,0x98+24,0x140000000)
        struct.pack_into('<H',raw,0x98+70,0x20|0x40|0x100);self.target.write_bytes(raw)
        info=StaticAnalysis(self.target).preflight()
        self.assertEqual(info['entry'],'0x140001000');self.assertEqual(info['architecture'],'x86_64')
        self.assertTrue(info['pe_security']['high_entropy_va'])
    def test_damaged_elf_never_produces_a_clean_audit(self):
        self.target.write_bytes(b'\x7fELF'+b'\0'*100)
        with self.assertRaises(ValueError):StaticInspectionWorker('security_audit',self.target).analyze()
    def test_mutating_target_during_string_scan_discards_results(self):
        def changed():self.target.write_bytes(b'changed')
        service=StaticAnalysis(self.target,changed)
        with self.assertRaisesRegex(ValueError,'değişti'):service.strings()
    def test_certificate_offset_outside_file_does_not_report_valid_table(self):
        raw=bytearray(self.target.read_bytes());struct.pack_into('<I',raw,0x98+92,16)
        struct.pack_into('<II',raw,0x98+96+4*8,999999,16);self.target.write_bytes(raw)
        o=StaticInspectionWorker('security_audit',self.target).analyze()['observations']
        self.assertTrue(o['certificate_table_declared']);self.assertFalse(o['certificate_table_in_file'])
    def test_real_elf_audit_and_stderr_capture_work(self):
        r=StaticInspectionWorker('security_audit','/usr/bin/true').analyze()
        self.assertEqual(r['format'],'ELF');self.assertIn(r['observations']['elf_type'],('DYN','EXEC'))
        self.assertTrue(r['raw_readelf'].strip())
        raw,warning=StaticAnalysis(self.target).command([sys.executable,'-c','import sys;print("out");print("warn",file=sys.stderr)'],capture_stderr=True)
        self.assertEqual(raw.strip(),'out');self.assertEqual(warning.strip(),'warn')
    def test_unknown_format_is_not_called_secure(self):
        self.target.write_bytes(b'unknown format')
        with self.assertRaisesRegex(ValueError,'desteklenmiyor'):StaticInspectionWorker('security_audit',self.target).analyze()
    def test_nonenglish_desktop_keeps_elf_header_parsing_stable(self):
        original=StaticAnalysis.command;environments=[]
        def command(service,args,**kwargs):
            environments.append(kwargs.get('env',{}));return original(service,args,**kwargs)
        with patch.dict(os.environ,{'LC_ALL':'tr_TR.UTF-8'}),patch.object(StaticAnalysis,'command',new=command):
            result=StaticInspectionWorker('security_audit','/usr/bin/true').analyze()
        self.assertEqual(result['format'],'ELF');self.assertEqual(environments[0]['LC_ALL'],'C')
    def test_cancelled_static_inspection_does_not_continue(self):
        worker=StaticInspectionWorker('strings',self.target);worker.cancel()
        with self.assertRaises(McpCancelled):worker.analyze()
    def test_progress_is_real_byte_coverage(self):
        self.target.write_bytes(b'\x00'*70000+b'FinalEvidence')
        events=[];r=StaticAnalysis(self.target,progress=events.append).strings()
        self.assertEqual(events[-1]['bytes_read'],self.target.stat().st_size)
        self.assertEqual(events[-1]['status'],'completed');self.assertEqual(r['scanned_bytes'],self.target.stat().st_size)

if __name__=='__main__':unittest.main(verbosity=2)

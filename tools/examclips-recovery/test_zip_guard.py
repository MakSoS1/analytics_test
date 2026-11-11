import io,zipfile,unittest
from zip_guard import checked_members
def archive(names):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w') as z:
        for name in names:z.writestr(name,'x')
    b.seek(0);return zipfile.ZipFile(b)
class GuardTests(unittest.TestCase):
    def test_valid_case(self):
        with archive(['run.json','rul01/result.json']) as z:self.assertEqual(len(checked_members(z,'rul01')),2)
    def test_real_primary_layout(self):
        with archive(['run.json','selected-manifest.json','rul01/result.json']) as z:self.assertEqual(len(checked_members(z,'rul01')),3)
    def test_traversal(self):
        for name in ['../key','/tmp/key','rul01/../../key','rul01\\key']:
            with self.subTest(name=name),archive([name]) as z,self.assertRaises(ValueError):checked_members(z,'rul01')
    def test_duplicate(self):
        with archive(['rul01/a','rul01/A']) as z,self.assertRaises(ValueError):checked_members(z,'rul01')
    def test_wrong_case(self):
        with archive(['rul02/result.json']) as z,self.assertRaises(ValueError):checked_members(z,'rul01')
    def test_missing_part(self):
        with archive(['encryption.json','parts.json']) as z,self.assertRaises(ValueError):checked_members(z,outer=True)
    def test_valid_part(self):
        with archive(['encryption.json','parts.json','evidence.enc.part']) as z:self.assertEqual(len(checked_members(z,outer=True)),3)
    def test_symlink(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            i=zipfile.ZipInfo('rul01/link');i.create_system=3;i.external_attr=0o120777<<16;z.writestr(i,'/tmp/key')
        b.seek(0)
        with zipfile.ZipFile(b) as z,self.assertRaises(ValueError):checked_members(z,'rul01')
if __name__=='__main__':unittest.main()

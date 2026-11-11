import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE=Path(__file__).with_name('native-dialog.py')

class NativeDialogTests(unittest.TestCase):
    def module(self):
        self.assertTrue(MODULE.is_file(),'real native dialog driver is implemented')
        spec=importlib.util.spec_from_file_location('native_dialog',MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

    def test_selects_only_a_new_chrome_save_dialog(self):
        m=self.module();before=[{'id':'100','name':'ExamClips — Google Chrome','class':'google-chrome'}]
        unrelated={'id':'200','name':'Save File','class':'unrelated-app','dialog':True}
        dialog={'id':'300','name':'Save File','class':'google-chrome','dialog':True,'transient_for':'100'}
        self.assertEqual(m.choose_dialog(before,before+[unrelated,dialog])['id'],'300')
        self.assertIsNone(m.choose_dialog(before,before+[unrelated]))
        self.assertIsNone(m.choose_dialog([dialog],[dialog]))

    def test_ambiguous_dialogs_fail_instead_of_typing_into_an_arbitrary_window(self):
        m=self.module();before=[{'id':'100','name':'ExamClips','class':'google-chrome'}]
        after=[{'id':str(i),'name':'Save File','class':'google-chrome','dialog':True,'transient_for':'100'} for i in (200,300)]
        with self.assertRaisesRegex(ValueError,'AMBIGUOUS_SAVE_DIALOG'):m.choose_dialog(before,after)

    def test_destination_must_be_new_and_inside_the_owned_case_directory(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);good=root/'native-clip.mp4'
            self.assertEqual(m.validate_destination(good,root),good)
            good.write_bytes(b'protected old file')
            with self.assertRaisesRegex(ValueError,'DESTINATION_EXISTS'):m.validate_destination(good,root)
            with self.assertRaisesRegex(ValueError,'OUTSIDE_CASE_DIRECTORY'):m.validate_destination(root.parent/'elsewhere.mp4',root)
            self.assertEqual(good.read_bytes(),b'protected old file')

if __name__=='__main__':unittest.main()

"""Run the explicit hosted release gate without imports from another checkout."""
import importlib.abc
import importlib.machinery
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]


class ReleaseOnly(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if (fullname in ('catknows','hosted') or fullname.startswith(('catknows.','hosted.','test_'))):
            spec=importlib.machinery.PathFinder.find_spec(fullname,path if path is not None else[str(ROOT)])
            if spec is None:
                raise ModuleNotFoundError('Module is outside hosted release: '+fullname)
            if spec.origin and spec.origin!='namespace' and not Path(spec.origin).resolve().is_relative_to(ROOT):
                raise ImportError('Non-release source rejected')
            return spec


def main():
    sys.path.insert(0,str(ROOT))
    finder=ReleaseOnly();sys.meta_path.insert(0,finder)
    try:
        gate=json.loads((ROOT/'hosted/deploy/test-gate.json').read_text())
        manifest=json.loads((ROOT/'hosted/deploy/probe/publish-manifest.json').read_text())
        allowed=set(manifest['files'])
        if any(name+'.py' not in allowed or not(ROOT/(name+'.py')).is_file()for name in gate['modules']):
            raise ValueError('Test gate contains an excluded module')
        suite=unittest.defaultTestLoader.loadTestsFromNames(gate['modules'])
        if suite.countTestCases()!=gate['expected_tests']:
            raise ValueError('Hosted release test count changed; review the gate')
        result=unittest.TextTestRunner(verbosity=1).run(suite)
        print(json.dumps({'isolated_runtime':True,'tests_run':result.testsRun,
            'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped)},sort_keys=True))
        return 0 if result.wasSuccessful()and not result.skipped else 1
    finally:sys.meta_path.remove(finder)


if __name__=='__main__':raise SystemExit(main())

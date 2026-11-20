"""Copy a small explicit Docker context; never send the repository to Docker."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=Path(__file__).with_name('context-manifest.json')
SECRET=re.compile(rb'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|'
    rb'eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|'
    rb'sb_secret_[A-Za-z0-9_-]{16,}|sk_live_[A-Za-z0-9]{16,}|'
    rb'gh[pousr]_[A-Za-z0-9]{24,})')
EMAIL=re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


def prepare(service, output, root=ROOT):
    output=Path(output).absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('Build output must be a new directory')
    files=json.loads(MANIFEST.read_text())[service]
    with tempfile.TemporaryDirectory(prefix='stealth-context-',dir=output.parent) as temporary:
        stage=Path(temporary)/'context';stage.mkdir(mode=0o700)
        for name in files:
            source=root/name
            if source.is_symlink() or not source.resolve().is_relative_to(root.resolve()) or not source.is_file():
                raise ValueError('Build source must be a regular repository file')
            data=source.read_bytes()
            if SECRET.search(data) or EMAIL.search(data):
                raise ValueError('Potential private data in build source: '+name)
            destination=stage/name;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data)
        # Defense in depth if a caller accidentally adds local files afterward.
        shutil.copyfile(root/'.dockerignore',stage/'.dockerignore')
        stage.rename(output)
    return len(files)+1


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--service',choices=('gateway','browser','gateway-probe','browser-probe'),required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:count=prepare(args.service,args.output)
    except Exception:raise SystemExit('Build context preparation refused') from None
    print(f'OK {args.service} build context: {count} allowlisted files; no build performed')


if __name__=='__main__':main()

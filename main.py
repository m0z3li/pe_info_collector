import os
import glob
import hashlib
import math
import sqlite3
import pefile
import json
from datetime import datetime

def calc_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def get_hashes(data):
    return {
        'sha256': hashlib.sha256(data).hexdigest(),
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest()
    }

def is_packed(pe):
    # 엔트로피 기반 패킹 탐지 (시그니처 기반으로 바꾸려면 별도 구현 필요)
    for section in pe.sections:
        if calc_entropy(section.get_data()) > 7.5:
            return True
    return False

def get_code_signing(pe_path):
    try:
        pe = pefile.PE(pe_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            return True
    except Exception:
        pass
    return False

def get_pdb_info(pe):
    try:
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            dbg = entry.entry
            if hasattr(dbg, 'PdbFileName'):
                return dbg.PdbFileName.decode(errors='ignore')
    except Exception:
        pass
    return None

def get_resource_info(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resources.append(str(resource_type.name or resource_type.struct.Id))
    return ','.join(resources)

def get_sections_info(pe):
    sections = []
    for s in pe.sections:
        section_data = s.get_data()
        sections.append({
            'name': s.Name.decode(errors='ignore').strip('\x00'),
            'entropy': calc_entropy(section_data),
            'size': s.SizeOfRawData,
            'virtual_size': s.Misc_VirtualSize,
            'characteristics': hex(s.Characteristics),
            'sha256': hashlib.sha256(section_data).hexdigest() if section_data else None,
            'md5': hashlib.md5(section_data).hexdigest() if section_data else None
        })
    return sections

def get_imports(pe):
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors='ignore')
            for imp in entry.imports:
                imports.append(f"{dll}:{imp.name.decode(errors='ignore') if imp.name else imp.ordinal}")
    return ','.join(imports)

def get_exports(pe):
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(exp.name.decode(errors='ignore') if exp.name else str(exp.ordinal))
    return ','.join(exports)

def get_version_info(pe):
    info = {}
    try:
        if hasattr(pe, 'FileInfo'):
            for fileinfo in pe.FileInfo:
                if isinstance(fileinfo, list):
                    for subinfo in fileinfo:
                        if hasattr(subinfo, 'Key') and subinfo.Key == b'StringFileInfo':
                            for st in getattr(subinfo, 'StringTable', []):
                                try:
                                    info.update({k.decode(errors='ignore'): v.decode(errors='ignore') for k, v in st.entries.items()})
                                except Exception:
                                    continue
                elif hasattr(fileinfo, 'Key') and fileinfo.Key == b'StringFileInfo':
                    for st in getattr(fileinfo, 'StringTable', []):
                        try:
                            info.update({k.decode(errors='ignore'): v.decode(errors='ignore') for k, v in st.entries.items()})
                        except Exception:
                            continue
    except Exception as e:
        print(f"버전 정보 분석 중 오류 발생: {e}")
    return info

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS pe_info (
            path TEXT PRIMARY KEY,
            sha256 TEXT,
            md5 TEXT,
            sha1 TEXT,
            entropy REAL,
            packed INTEGER,
            size INTEGER,
            code_signed INTEGER,
            created TEXT,
            accessed TEXT,
            modified TEXT,
            sections TEXT,
            sections_hashes TEXT,
            imports TEXT,
            exports TEXT,
            pdb TEXT,
            resources TEXT,
            timestamp INTEGER,
            machine TEXT,
            subsystem TEXT,
            entrypoint TEXT,
            tls_callbacks TEXT,
            company_name TEXT,
            product_name TEXT,
            file_description TEXT,
            file_version TEXT,
            has_rich_header INTEGER,
            dll_characteristics TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_to_sqlite(db_path, results):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    for info in results:
        if info:
            c.execute('''
                INSERT OR REPLACE INTO pe_info VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                info.get('path'),
                info.get('sha256'),
                info.get('md5'),
                info.get('sha1'),
                info.get('entropy'),
                int(info.get('packed', 0)) if info.get('packed') is not None else None,
                info.get('size'),
                int(info.get('code_signed', 0)) if info.get('code_signed') is not None else None,
                str(info.get('created')) if info.get('created') is not None else None,
                str(info.get('accessed')) if info.get('accessed') is not None else None,
                str(info.get('modified')) if info.get('modified') is not None else None,
                info.get('sections'),
                info.get('sections_hashes'),
                info.get('imports'),
                info.get('exports'),
                info.get('pdb'),
                info.get('resources'),
                info.get('timestamp'),
                info.get('machine'),
                info.get('subsystem'),
                info.get('entrypoint'),
                info.get('tls_callbacks'),
                info.get('company_name'),
                info.get('product_name'),
                info.get('file_description'),
                info.get('file_version'),
                int(info.get('has_rich_header', 0)),
                info.get('dll_characteristics')
            ))
    conn.commit()
    conn.close()

def is_already_analyzed(db_path, sha256, path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT path FROM pe_info WHERE sha256=? AND path=?", (sha256, path))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_dll_characteristics(pe):
    # DLL Characteristics 플래그 분석
    flags = []
    val = pe.OPTIONAL_HEADER.DllCharacteristics
    if val & 0x40:
        flags.append('ASLR')
    if val & 0x100:
        flags.append('NX/DEP')
    if val & 0x200:
        flags.append('NoIsolation')
    if val & 0x400:
        flags.append('NoSEH')
    if val & 0x800:
        flags.append('NoBind')
    if val & 0x1000:
        flags.append('WDMDriver')
    if val & 0x2000:
        flags.append('GuardCF')
    if val & 0x4000:
        flags.append('TerminalServerAware')
    return ','.join(flags) if flags else 'None'

def analyze_pe_file(pe_path):
    try:
        pe = pefile.PE(pe_path)
        with open(pe_path, 'rb') as f:
            data = f.read()
        hashes = get_hashes(data)
        version_info = get_version_info(pe)
        sections_info = get_sections_info(pe)
        info = {
            'path': pe_path,
            'sha256': hashes['sha256'],
            'md5': hashes['md5'],
            'sha1': hashes['sha1'],
            'entropy': calc_entropy(data),
            'packed': is_packed(pe),
            'size': os.path.getsize(pe_path),
            'code_signed': get_code_signing(pe_path),
            'created': datetime.fromtimestamp(os.path.getctime(pe_path)),
            'accessed': datetime.fromtimestamp(os.path.getatime(pe_path)),
            'modified': datetime.fromtimestamp(os.path.getmtime(pe_path)),
            'sections': json.dumps(sections_info, ensure_ascii=False),
            'sections_hashes': json.dumps([
                {'name': s['name'], 'sha256': s['sha256'], 'md5': s['md5']}
                for s in sections_info
            ], ensure_ascii=False),
            'imports': get_imports(pe),
            'exports': get_exports(pe),
            'pdb': get_pdb_info(pe),
            'resources': get_resource_info(pe),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'machine': hex(pe.FILE_HEADER.Machine),
            'subsystem': hex(pe.OPTIONAL_HEADER.Subsystem),
            'entrypoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'tls_callbacks': str(getattr(pe, 'DIRECTORY_ENTRY_TLS', None)),
            'company_name': version_info.get('CompanyName', ''),
            'product_name': version_info.get('ProductName', ''),
            'file_description': version_info.get('FileDescription', ''),
            'file_version': version_info.get('FileVersion', ''),
            'has_rich_header': has_rich_header(pe_path),
            'dll_characteristics': get_dll_characteristics(pe),  # 추가
        }
        return info
    except Exception as e:
        print(f"Error analyzing {pe_path}: {e}")
        return None

def has_rich_header(pe_path):
    try:
        pe = pefile.PE(pe_path)
        # pefile은 rich_header 속성을 제공합니다.
        return hasattr(pe, 'rich_header') and pe.rich_header is not None
    except Exception:
        return False

def main(data_path, db_path='pe_info.db'):
    init_db(db_path)
    results = []
    if os.path.isfile(data_path):
        if data_path.lower().endswith(('.exe', '.dll')):
            try:
                with open(data_path, 'rb') as f:
                    data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                if is_already_analyzed(db_path, sha256, data_path):
                    print(f"이미 분석된 파일입니다: {data_path}")
                    return
                print(f"분석 중: {data_path} ...", end='', flush=True)
                info = analyze_pe_file(data_path)
                if info:
                    results.append(info)
                print(" 완료")
            except Exception as e:
                print(f"파일 분석 중 오류: {e}")
        else:
            print("PE 파일(.exe, .dll)만 입력 가능합니다. 파일 경로를 다시 입력해주세요.")
            return
    elif os.path.isdir(data_path):
        # 폴더 내의 PE 파일만 분석
        pe_files = []
        for root, dirs, files in os.walk(data_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll')):
                    pe_files.append(os.path.join(root, file))
        total = len(pe_files)
        print(f"총 {total}개 파일 분석 시작")
        for idx, pe_path in enumerate(pe_files, 1):
            try:
                with open(pe_path, 'rb') as f:
                    data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                if is_already_analyzed(db_path, sha256, pe_path):
                    print(f"[{idx}/{total}] 이미 분석된 파일입니다: {pe_path}")
                    continue
                print(f"[{idx}/{total}] 분석 중: {pe_path} ...", end='', flush=True)
                info = analyze_pe_file(pe_path)
                if info:
                    results.append(info)
                print(" 완료")
            except Exception as e:
                print(f"[{idx}/{total}] 파일 분석 중 오류: {pe_path} ({e})")
    else:
        print(f"입력하신 경로 또는 파일이 존재하지 않거나 지원하지 않는 형식입니다: {data_path}")
        return
    if results:
        save_to_sqlite(db_path, results)
    print(f"분석 완료! {len(results)}개 파일이 DB에 저장되었습니다.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2 or sys.argv[1] in ['--h', '--help', '-h', '-help']:
        print("사용법: python pe_info_collector.py <데이터_경로 또는 파일> [DB경로]")
        print("옵션:")
        print("  --h, --help, -h, -help   도움말 출력")
        print("예시:")
        print("  python pe_info_collector.py C:\\samples")
        print("  python pe_info_collector.py C:\\samples result.db")
    else:
        data_path = sys.argv[1]
        db_path = sys.argv[2] if len(sys.argv) > 2 else 'pe_info.db'
        main(data_path, db_path)
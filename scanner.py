#!/usr/bin/env python3
"""
Project Scanner - プロジェクト構造分析ツール

機能:
- フォルダ配下の全ファイル一覧と行数
- 拡張子別統計
- 各ファイルの先頭N行・末尾N行（空行スキップ）
- 関数一覧抽出（AST使用）
- 拡張子別ファイル結合（Concat）
- HTMLレポート出力
"""

__version__ = "0.13"

import os
import ast
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class FileInfo:
    """ファイル情報"""
    path: Path
    relative_path: str
    extension: str
    line_count: int
    size: int  # bytes
    first_lines: List[str] = field(default_factory=list)
    last_lines: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """スキャン結果"""
    root_path: Path
    scan_time: datetime
    total_files: int
    total_folders: int
    total_lines: int
    extension_stats: Dict[str, int]  # {".py": 25, ".csv": 7, ...}
    files: List[FileInfo]
    all_functions: List[Tuple[str, str]]  # [(file, func_name), ...]
    all_classes: List[Tuple[str, str]]  # [(file, class_name), ...]


class ProjectScanner:
    """プロジェクトスキャナー"""

    # スキップするフォルダ
    SKIP_DIRS = {
        '.git', '.svn', '.hg',
        'node_modules', '__pycache__', '.venv', 'venv',
        '.idea', '.vscode', '.vs',
        'dist', 'build', 'target', 'bin', 'obj'
    }

    # バイナリ拡張子（行数カウントしない）
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.mp3', '.mp4', '.wav', '.avi', '.mov',
        '.pyc', '.pyo', '.class', '.o', '.obj'
    }

    def __init__(self,
                 head_lines: int = 3,
                 tail_lines: int = 3,
                 skip_empty: bool = True):
        """
        Args:
            head_lines: 取得する先頭行数
            tail_lines: 取得する末尾行数
            skip_empty: 空行をスキップするか
        """
        self.head_lines = head_lines
        self.tail_lines = tail_lines
        self.skip_empty = skip_empty

    def scan(self, root_path: str) -> ScanResult:
        """プロジェクトをスキャン"""
        root = Path(root_path).resolve()
        if not root.exists():
            raise ValueError(f"パスが存在しません: {root}")
        if not root.is_dir():
            raise ValueError(f"ディレクトリではありません: {root}")

        files: List[FileInfo] = []
        folder_count = 0
        extension_stats: Dict[str, int] = defaultdict(int)
        all_functions: List[Tuple[str, str]] = []
        all_classes: List[Tuple[str, str]] = []
        total_lines = 0

        for dirpath, dirnames, filenames in os.walk(root):
            # スキップするフォルダを除外
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            folder_count += 1

            for filename in filenames:
                file_path = Path(dirpath) / filename
                relative_path = file_path.relative_to(root)
                extension = file_path.suffix.lower()

                # 拡張子統計
                ext_key = extension if extension else "(no ext)"
                extension_stats[ext_key] += 1

                # ファイル情報取得
                file_info = self._analyze_file(file_path, str(relative_path), extension)
                files.append(file_info)
                total_lines += file_info.line_count

                # 関数・クラス情報を集約
                for func in file_info.functions:
                    all_functions.append((str(relative_path), func))
                for cls in file_info.classes:
                    all_classes.append((str(relative_path), cls))

        return ScanResult(
            root_path=root,
            scan_time=datetime.now(),
            total_files=len(files),
            total_folders=folder_count,
            total_lines=total_lines,
            extension_stats=dict(sorted(extension_stats.items(),
                                        key=lambda x: x[1], reverse=True)),
            files=files,
            all_functions=all_functions,
            all_classes=all_classes
        )

    def _analyze_file(self, path: Path, relative_path: str, extension: str) -> FileInfo:
        """ファイルを分析"""
        size = path.stat().st_size

        # バイナリファイルは行数カウントしない
        if extension in self.BINARY_EXTENSIONS:
            return FileInfo(
                path=path,
                relative_path=relative_path,
                extension=extension,
                line_count=0,
                size=size
            )

        # テキストファイルの分析
        try:
            lines = self._read_lines(path)
            first_lines = self._get_first_lines(lines)
            last_lines = self._get_last_lines(lines)
            functions, classes = self._extract_definitions(path, extension)

            return FileInfo(
                path=path,
                relative_path=relative_path,
                extension=extension,
                line_count=len(lines),
                size=size,
                first_lines=first_lines,
                last_lines=last_lines,
                functions=functions,
                classes=classes
            )
        except Exception as e:
            # 読み取りエラーの場合
            return FileInfo(
                path=path,
                relative_path=relative_path,
                extension=extension,
                line_count=0,
                size=size
            )

    def _read_lines(self, path: Path) -> List[str]:
        """ファイルの全行を読み取り"""
        encodings = ['utf-8', 'utf-8-sig', 'cp932', 'shift_jis', 'latin-1']
        for encoding in encodings:
            try:
                with open(path, 'r', encoding=encoding) as f:
                    return f.readlines()
            except (UnicodeDecodeError, UnicodeError):
                continue
        return []

    def _get_first_lines(self, lines: List[str]) -> List[str]:
        """先頭N行を取得（空行スキップ対応）"""
        result = []
        for line in lines:
            if self.skip_empty and not line.strip():
                continue
            result.append(line.rstrip())
            if len(result) >= self.head_lines:
                break
        return result

    def _get_last_lines(self, lines: List[str]) -> List[str]:
        """末尾N行を取得（空行スキップ対応）"""
        result = []
        for line in reversed(lines):
            if self.skip_empty and not line.strip():
                continue
            result.append(line.rstrip())
            if len(result) >= self.tail_lines:
                break
        return list(reversed(result))

    def _extract_definitions(self, path: Path, extension: str) -> Tuple[List[str], List[str]]:
        """関数・クラス定義を抽出（Python用AST）"""
        functions = []
        classes = []

        if extension != '.py':
            return functions, classes

        try:
            with open(path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.AsyncFunctionDef):
                    functions.append(f"async {node.name}")
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
        except:
            pass

        return functions, classes


class HTMLReportGenerator:
    """HTMLレポート生成"""

    def generate(self, result: ScanResult, output_dir: str) -> Tuple[str, str]:
        """
        レポートを生成

        Returns:
            (概要レポートパス, 詳細レポートパス)
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        index_path = output_path / "index.html"
        detail_path = output_path / "detail.html"

        # 概要レポート
        index_html = self._generate_index(result)
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(index_html)

        # 詳細レポート
        detail_html = self._generate_detail(result)
        with open(detail_path, 'w', encoding='utf-8') as f:
            f.write(detail_html)

        return str(index_path), str(detail_path)

    def _generate_index(self, result: ScanResult) -> str:
        """概要レポートHTML"""
        ext_rows = ""
        for ext, count in result.extension_stats.items():
            ext_rows += f"<tr><td>{ext}</td><td>{count}</td></tr>\n"

        file_rows = ""
        for f in sorted(result.files, key=lambda x: x.relative_path):
            file_rows += f"<tr><td>{f.relative_path}</td><td>{f.extension}</td><td>{f.line_count:,}</td><td>{f.size:,}</td></tr>\n"

        func_rows = ""
        for file_path, func_name in result.all_functions:
            func_rows += f"<tr><td>{file_path}</td><td>{func_name}</td></tr>\n"

        class_rows = ""
        for file_path, class_name in result.all_classes:
            class_rows += f"<tr><td>{file_path}</td><td>{class_name}</td></tr>\n"

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Scanner - 概要レポート</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            line-height: 1.6;
        }}
        h1 {{ color: #00d9ff; margin-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin: 30px 0 15px 0; border-bottom: 2px solid #ff6b6b; padding-bottom: 5px; }}
        h3 {{ color: #feca57; margin: 20px 0 10px 0; }}
        .meta {{ color: #888; margin-bottom: 20px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .card {{
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .card .number {{ font-size: 2em; color: #00d9ff; font-weight: bold; }}
        .card .label {{ color: #888; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
        }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #0f3460; color: #00d9ff; }}
        tr:hover {{ background: #1f4068; }}
        a {{ color: #00d9ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .nav {{ margin-bottom: 20px; }}
        .nav a {{
            background: #0f3460;
            padding: 10px 20px;
            border-radius: 5px;
            margin-right: 10px;
        }}
        .version {{
            position: fixed;
            top: 10px;
            right: 20px;
            background: #0f3460;
            padding: 5px 15px;
            border-radius: 5px;
            font-size: 0.85em;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="version">v{__version__}</div>
    <div class="nav">
        <a href="index.html">概要</a>
        <a href="detail.html">詳細</a>
    </div>

    <h1>Project Scanner - 概要レポート</h1>
    <p class="meta">
        対象: {result.root_path}<br>
        スキャン日時: {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
    </p>

    <h2>サマリー</h2>
    <div class="summary">
        <div class="card">
            <div class="number">{result.total_folders}</div>
            <div class="label">フォルダ数</div>
        </div>
        <div class="card">
            <div class="number">{result.total_files}</div>
            <div class="label">ファイル数</div>
        </div>
        <div class="card">
            <div class="number">{result.total_lines:,}</div>
            <div class="label">総行数</div>
        </div>
        <div class="card">
            <div class="number">{len(result.extension_stats)}</div>
            <div class="label">拡張子の種類</div>
        </div>
        <div class="card">
            <div class="number">{len(result.all_functions)}</div>
            <div class="label">関数数（Python）</div>
        </div>
        <div class="card">
            <div class="number">{len(result.all_classes)}</div>
            <div class="label">クラス数（Python）</div>
        </div>
    </div>

    <h2>拡張子別統計</h2>
    <table>
        <tr><th>拡張子</th><th>ファイル数</th></tr>
        {ext_rows}
    </table>

    <h2>ファイル一覧</h2>
    <table>
        <tr><th>パス</th><th>拡張子</th><th>行数</th><th>サイズ(bytes)</th></tr>
        {file_rows}
    </table>

    <h2>関数一覧（Python）</h2>
    <table>
        <tr><th>ファイル</th><th>関数名</th></tr>
        {func_rows if func_rows else "<tr><td colspan='2'>Pythonファイルがないか、関数が見つかりません</td></tr>"}
    </table>

    <h2>クラス一覧（Python）</h2>
    <table>
        <tr><th>ファイル</th><th>クラス名</th></tr>
        {class_rows if class_rows else "<tr><td colspan='2'>Pythonファイルがないか、クラスが見つかりません</td></tr>"}
    </table>
</body>
</html>"""

    def _generate_detail(self, result: ScanResult) -> str:
        """詳細レポートHTML"""
        file_details = ""
        for f in sorted(result.files, key=lambda x: x.relative_path):
            first_lines_html = "<br>".join(
                f"<code>{self._escape_html(line)}</code>" for line in f.first_lines
            ) if f.first_lines else "<em>（取得できません）</em>"

            last_lines_html = "<br>".join(
                f"<code>{self._escape_html(line)}</code>" for line in f.last_lines
            ) if f.last_lines else "<em>（取得できません）</em>"

            funcs = ", ".join(f.functions) if f.functions else "-"
            classes = ", ".join(f.classes) if f.classes else "-"

            file_details += f"""
            <div class="file-card">
                <h3>{f.relative_path}</h3>
                <p><strong>拡張子:</strong> {f.extension} | <strong>行数:</strong> {f.line_count:,} | <strong>サイズ:</strong> {f.size:,} bytes</p>
                <div class="code-section">
                    <h4>先頭行</h4>
                    <div class="code-block">{first_lines_html}</div>
                </div>
                <div class="code-section">
                    <h4>末尾行</h4>
                    <div class="code-block">{last_lines_html}</div>
                </div>
                <p><strong>関数:</strong> {funcs}</p>
                <p><strong>クラス:</strong> {classes}</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Scanner - 詳細レポート</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            line-height: 1.6;
        }}
        h1 {{ color: #00d9ff; margin-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin: 30px 0 15px 0; }}
        h3 {{ color: #feca57; margin: 0 0 10px 0; }}
        h4 {{ color: #48dbfb; margin: 10px 0 5px 0; font-size: 0.9em; }}
        .meta {{ color: #888; margin-bottom: 20px; }}
        .nav {{ margin-bottom: 20px; }}
        .nav a {{
            background: #0f3460;
            padding: 10px 20px;
            border-radius: 5px;
            margin-right: 10px;
            color: #00d9ff;
            text-decoration: none;
        }}
        .nav a:hover {{ background: #1f4068; }}
        .file-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }}
        .code-section {{ margin: 15px 0; }}
        .code-block {{
            background: #0d1b2a;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        code {{ color: #98c379; }}
        .version {{
            position: fixed;
            top: 10px;
            right: 20px;
            background: #0f3460;
            padding: 5px 15px;
            border-radius: 5px;
            font-size: 0.85em;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="version">v{__version__}</div>
    <div class="nav">
        <a href="index.html">概要</a>
        <a href="detail.html">詳細</a>
    </div>

    <h1>Project Scanner - 詳細レポート</h1>
    <p class="meta">
        対象: {result.root_path}<br>
        スキャン日時: {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
    </p>

    <h2>各ファイルの詳細</h2>
    {file_details}
</body>
</html>"""

    def _escape_html(self, text: str) -> str:
        """HTMLエスケープ"""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


class FileConcatenator:
    """ファイル結合"""

    def concat_by_extension(self, result: ScanResult, output_dir: str,
                           extensions: Optional[List[str]] = None) -> Dict[str, str]:
        """
        拡張子別にファイルを結合

        Args:
            result: スキャン結果
            output_dir: 出力先
            extensions: 対象拡張子（Noneなら全て）

        Returns:
            {拡張子: 出力ファイルパス}
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # 拡張子別にファイルをグループ化
        ext_files: Dict[str, List[FileInfo]] = defaultdict(list)
        for f in result.files:
            if extensions is None or f.extension in extensions:
                if f.extension and f.extension not in ProjectScanner.BINARY_EXTENSIONS:
                    ext_files[f.extension].append(f)

        outputs = {}
        for ext, files in ext_files.items():
            ext_name = ext.lstrip('.')
            output_file = output_path / f"all_{ext_name}{ext}"

            with open(output_file, 'w', encoding='utf-8') as out:
                for f in sorted(files, key=lambda x: x.relative_path):
                    out.write(f"\n{'='*60}\n")
                    out.write(f"# File: {f.relative_path}\n")
                    out.write(f"{'='*60}\n\n")

                    try:
                        with open(f.path, 'r', encoding='utf-8') as src:
                            out.write(src.read())
                    except:
                        out.write("# (読み取りエラー)\n")
                    out.write("\n")

            outputs[ext] = str(output_file)

        return outputs


def main():
    parser = argparse.ArgumentParser(
        description='Project Scanner - プロジェクト構造分析ツール'
    )
    parser.add_argument('path', help='スキャン対象のフォルダパス')
    parser.add_argument('--head', type=int, default=3, help='先頭行数（デフォルト: 3）')
    parser.add_argument('--tail', type=int, default=3, help='末尾行数（デフォルト: 3）')
    parser.add_argument('--output', '-o', default='./output', help='出力先フォルダ')
    parser.add_argument('--concat', action='store_true', help='拡張子別にファイル結合')
    parser.add_argument('--concat-ext', nargs='+', help='結合対象の拡張子（例: .py .js）')

    args = parser.parse_args()

    print(f"スキャン開始: {args.path}")

    scanner = ProjectScanner(head_lines=args.head, tail_lines=args.tail)
    result = scanner.scan(args.path)

    print(f"\n=== スキャン完了 ===")
    print(f"フォルダ数: {result.total_folders}")
    print(f"ファイル数: {result.total_files}")
    print(f"総行数: {result.total_lines:,}")
    print(f"拡張子の種類: {len(result.extension_stats)}")
    print(f"関数数: {len(result.all_functions)}")
    print(f"クラス数: {len(result.all_classes)}")

    # HTMLレポート生成
    generator = HTMLReportGenerator()
    index_path, detail_path = generator.generate(result, args.output)
    print(f"\n=== レポート生成 ===")
    print(f"概要: {index_path}")
    print(f"詳細: {detail_path}")

    # Concat
    if args.concat:
        concatenator = FileConcatenator()
        extensions = args.concat_ext if args.concat_ext else None
        concat_output = Path(args.output) / "concat"
        outputs = concatenator.concat_by_extension(result, str(concat_output), extensions)
        print(f"\n=== ファイル結合 ===")
        for ext, path in outputs.items():
            print(f"{ext}: {path}")

    print(f"\n完了!")


if __name__ == '__main__':
    main()

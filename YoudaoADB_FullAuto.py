name: 自动构建 + 自动更新版本号 + 自动发布

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: 设置 Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: 计算自动版本号 2.0 -> 2.1 -> 2.2...
        id: calc_ver
        shell: pwsh
        run: |
          $base = 2.0
          $ver = [math]::Round($base + ${{ github.run_number }} / 10, 1)
          echo "build_version=$ver" >> $env:GITHUB_OUTPUT

      - name: 自动写入版本号到 Python 代码
        shell: pwsh
        run: |
          (Get-Content YoudaoADB_FullAuto.py) -replace 'VERSION = ".*?"','VERSION = "${{ steps.calc_ver.outputs.build_version }}"' | Set-Content YoudaoADB_FullAuto.py

      - name: 安装依赖
        run: |
          pip install --upgrade pip
          pip install requests scapy pyinstaller

      - name: 编译单文件 EXE
        run: |
          pyinstaller -F -c YoudaoADB_FullAuto.py
          ren dist\YoudaoADB_FullAuto.exe YoudaoADB_FullAuto_v${{ steps.calc_ver.outputs.build_version }}.exe

      - name: 发布 Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: v${{ steps.calc_ver.outputs.build_version }}
          name: 有道词典笔ADB工具 v${{ steps.calc_ver.outputs.build_version }}
          body: |
            自动构建版本：v${{ steps.calc_ver.outputs.build_version }}
            作者：喂鸡 (Wei Ji)
            新增自动抓包功能，全流程无需手动输入
            (C) 2026 喂鸡 (Wei Ji) 版权所有
          files: dist/YoudaoADB_FullAuto_v${{ steps.calc_ver.outputs.build_version }}.exe

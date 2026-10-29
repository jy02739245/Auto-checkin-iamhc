#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：逻辑都在 src/ 下，保留这个名字方便 Actions 和本地习惯用法。"""

import sys

from src.checkin import main

if __name__ == "__main__":
    sys.exit(main())

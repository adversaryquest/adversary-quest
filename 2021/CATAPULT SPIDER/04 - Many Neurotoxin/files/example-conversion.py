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

""" Example Conversion

This script converts an image (e.g. png) into the format that is expected
by the remote classification service.
"""

# disable tensorflow logging:
import logging
import os

logging.disable(logging.WARNING)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import argparse
import base64
import tensorflow

def load_and_serialize_picture(path):
    """ Reads an image from given path and encodes it. """

    img_unprepared = tensorflow.keras.preprocessing.image.load_img(path)
    img = tensorflow.keras.preprocessing.image.img_to_array(img_unprepared) / 255.0

    assert img.shape == (180, 180, 3)

    return base64.b64encode(tensorflow.io.serialize_tensor(img).numpy()).decode()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dst")
    parser.add_argument("src")
    args = parser.parse_args()

    img = load_and_serialize_picture(args.src)

    with open(args.dst, "w") as writer:
        writer.write(img)

if __name__ == "__main__":
    main()

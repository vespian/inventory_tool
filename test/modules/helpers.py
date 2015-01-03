#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
# Copyright (c) 2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

def stringify(input_obj):
    """Convert in-place all hash/list elements to string

    Args:
        in: input object
    """

    for i, item in enumerate(input_obj):
        if isinstance(input_obj, dict):
            if isinstance(input_obj[item], dict) or isinstance(input_obj[item], list):
                stringify(input_obj[item])
            else:
                input_obj[item] = str(input_obj[item])
        elif isinstance(input_obj, list):
            if isinstance(input_obj[i], dict) or isinstance(input_obj[i], list):
                stringify(input_obj[i])
            else:
                input_obj[i] = str(item)

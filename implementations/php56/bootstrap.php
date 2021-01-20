<?php
/*
 * Copyright (C) 2020 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * Bootstrapping File for phpseclib
 *
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 */

if (extension_loaded('mbstring')) {
    // 2 - MB_OVERLOAD_STRING
    if (ini_get('mbstring.func_overload') & 2) {
        throw new \UnexpectedValueException(
            'Overloading of string functions using mbstring.func_overload ' .
            'is not supported by phpseclib.'
        );
    }
}

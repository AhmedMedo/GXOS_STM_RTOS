/* gxos Microcontroller Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef gxos_FILEPATH_H
#define gxos_FILEPATH_H

#include "platform/platform.h"

#include "platform/FileSystemLike.h"
#include "platform/FileLike.h"

namespace gxos {
/** \addtogroup platform */

/**
 * @class FileSystem
 * @ingroup platform
 */
class FileSystem;

class FilePath {
public:
    FilePath(const char* file_path);

    const char* fileName(void);

    bool          isFileSystem(void);
    FileSystemLike* fileSystem(void);

    bool    isFile(void);
    FileLike* file(void);
    bool    exists(void);

private:
    const char* file_name;
    FileBase* fb;
};

} // namespace gxos

#endif

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
#ifndef gxos_FILEBASE_H
#define gxos_FILEBASE_H

typedef int FILEHANDLE;

#include <cstdio>
#include <cstring>

#include "platform/platform.h"
#include "platform/SingletonPtr.h"
#include "platform/PlatformMutex.h"
#include "platform/NonCopyable.h"

namespace gxos {
/** \addtogroup platform */
/** @{*/

typedef enum {
    FilePathType,
    FileSystemPathType
} PathType;
/** @}*/

/**
 * @class FileBase
 * @ingroup platform
 */
class FileBase : private NonCopyable<FileBase> {
public:
    FileBase(const char *name, PathType t);
    virtual ~FileBase();

    const char* getName(void);
    PathType    getPathType(void);

    static FileBase *lookup(const char *name, unsigned int len);

    static FileBase *get(int n);

    /* disallow copy constructor and assignment operators */
private:
    static FileBase *_head;
    static SingletonPtr<PlatformMutex> _mutex;

    FileBase   *_next;
    const char * const _name;
    const PathType _path_type;
};

} // namespace gxos

#endif


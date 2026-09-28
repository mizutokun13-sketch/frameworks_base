/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * System clock functions.
 */

#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits>

#include <nativehelper/JNIHelp.h>
#include "jni.h"
#include "core_jni_helpers.h"

#include <utils/SystemClock.h>
#include <utils/Timers.h>
#include "hwcfg.h"

namespace android {

static jlong android_os_SystemClock_uptimeMillis()
{
    return (jlong)uptimeMillis();
}

static jlong android_os_SystemClock_uptimeNanos()
{
    return (jlong)uptimeNanos();
}

static jlong android_os_SystemClock_elapsedRealtime()
{
    jlong real = (jlong)elapsedRealtime();
    jlong offset = (jlong)hwcfg::uptimeOffsetMs();
    return real + offset;
}

static jlong android_os_SystemClock_elapsedRealtimeNanos()
{
    jlong real = (jlong)elapsedRealtimeNano();
    jlong offset_ms = (jlong)hwcfg::uptimeOffsetMs();
    return real + (offset_ms * 1000000LL);
}

/*
 * native public static long currentThreadTimeMillis();
 */
static jlong android_os_SystemClock_currentThreadTimeMillis()
{
    return nanoseconds_to_milliseconds(systemTime(SYSTEM_TIME_THREAD));
}

/*
 * native public static long currentThreadTimeMicro();
 */
static jlong android_os_SystemClock_currentThreadTimeMicro()
{
    return nanoseconds_to_microseconds(systemTime(SYSTEM_TIME_THREAD));
}

/*
 * native public static long currentTimeMicro();
 */
static jlong android_os_SystemClock_currentTimeMicro()
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

/*
 * JNI registration.
 */
static const JNINativeMethod gMethods[] = {
    { "uptimeMillis", "()J", (void*) android_os_SystemClock_uptimeMillis },
    { "uptimeNanos", "()J", (void*) android_os_SystemClock_uptimeNanos },
    { "elapsedRealtime", "()J", (void*) android_os_SystemClock_elapsedRealtime },
    { "elapsedRealtimeNanos", "()J", (void*) android_os_SystemClock_elapsedRealtimeNanos },

    // SystemClock doesn't have an implementation for these that we can directly call
    { "currentThreadTimeMillis", "()J",
            (void*) android_os_SystemClock_currentThreadTimeMillis },
    { "currentThreadTimeMicro", "()J",
            (void*) android_os_SystemClock_currentThreadTimeMicro },
    { "currentTimeMicro", "()J",
            (void*) android_os_SystemClock_currentTimeMicro },
};
int register_android_os_SystemClock(JNIEnv* env)
{
    return RegisterMethodsOrDie(env, "android/os/SystemClock", gMethods, NELEM(gMethods));
}

}; // namespace android

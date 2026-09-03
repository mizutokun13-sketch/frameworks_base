/*
 * Copyright (C) 2026 The Android Open Source Project
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

package android.hardware;

import android.os.SystemProperties;

import java.util.Locale;
import java.util.Random;

/**
 * Opt-in motion stream used by framework sensor tests.
 *
 * The simulator is package-scoped through an explicit comma-separated allowlist. It changes
 * continuous listener data only; the native sensor HAL, direct channels, and trigger sensors
 * remain untouched.
 */
final class MotionSensorSimulator {
    private static final String PROP_ENABLED = "persist.sys.hwcfg.motion.enabled";
    private static final String PROP_PACKAGES = "persist.sys.hwcfg.motion.packages";
    private static final String PROP_PROFILE = "persist.sys.hwcfg.motion.profile";
    private static final String PROP_INTENSITY = "persist.sys.hwcfg.motion.intensity";

    private static final String PROFILE_IDLE = "idle";
    private static final String PROFILE_WALKING = "walking";

    private static final long CONFIG_REFRESH_NS = 250_000_000L;
    private static final float GRAVITY = 9.80665f;
    private static final float DEG_TO_RAD = (float) (Math.PI / 180.0);

    private final String mPackageName;
    private final Random mRandom;
    private final float[] mNoise = new float[3];
    private final float[] mAngles = new float[3];
    private final float[] mRates = new float[3];

    private long mLastConfigRefreshNs;
    private long mStartTimestampNs;
    private long mLastTimestampNs;
    private String mConfigFingerprint = "";
    private String mProfile = PROFILE_IDLE;
    private float mIntensity = 1.0f;
    private boolean mEnabled;

    MotionSensorSimulator(String packageName) {
        mPackageName = packageName == null ? "" : packageName;
        long seed = 0x6a09e667f3bcc909L ^ mPackageName.hashCode()
                ^ System.identityHashCode(this);
        mRandom = new Random(seed);
    }

    /**
     * Replaces the continuous motion values in-place when the current package is enabled.
     */
    synchronized boolean transform(Sensor sensor, float[] values, long timestampNs) {
        if (sensor == null || values == null || values.length == 0) {
            return false;
        }

        final long nowNs = System.nanoTime();
        refreshConfig(nowNs);
        if (!mEnabled) {
            return false;
        }

        final long sampleTimestampNs = timestampNs > 0 ? timestampNs : nowNs;
        if (mStartTimestampNs == 0 || sampleTimestampNs < mLastTimestampNs) {
            mStartTimestampNs = sampleTimestampNs;
            mLastTimestampNs = sampleTimestampNs;
        }

        final float dtSeconds = clamp((sampleTimestampNs - mLastTimestampNs) * 1.0e-9f,
                0.001f, 0.1f);
        mLastTimestampNs = sampleTimestampNs;
        updateNoise(dtSeconds);

        final float t = (sampleTimestampNs - mStartTimestampNs) * 1.0e-9f;
        final boolean walking = PROFILE_WALKING.equals(mProfile);
        final float activity = mIntensity * (walking ? 1.0f : 0.22f);

        switch (sensor.getType()) {
            case Sensor.TYPE_ACCELEROMETER:
                writeAccelerometer(values, t, activity, walking, false);
                return true;
            case Sensor.TYPE_ACCELEROMETER_UNCALIBRATED:
                writeAccelerometer(values, t, activity, walking, true);
                return true;
            case Sensor.TYPE_LINEAR_ACCELERATION:
                writeLinearAcceleration(values, t, activity, walking);
                return true;
            case Sensor.TYPE_GRAVITY:
                writeGravity(values, t, activity);
                return true;
            case Sensor.TYPE_GYROSCOPE:
                writeGyroscope(values, t, activity, false);
                return true;
            case Sensor.TYPE_GYROSCOPE_UNCALIBRATED:
                writeGyroscope(values, t, activity, true);
                return true;
            case Sensor.TYPE_ROTATION_VECTOR:
            case Sensor.TYPE_GAME_ROTATION_VECTOR:
            case Sensor.TYPE_GEOMAGNETIC_ROTATION_VECTOR:
                writeRotationVector(values, t, activity);
                return true;
            case Sensor.TYPE_ORIENTATION:
                writeOrientation(values, t, activity);
                return true;
            default:
                return false;
        }
    }

    private void refreshConfig(long nowNs) {
        if (nowNs - mLastConfigRefreshNs < CONFIG_REFRESH_NS) {
            return;
        }
        mLastConfigRefreshNs = nowNs;

        final String enabled = SystemProperties.get(PROP_ENABLED, "0");
        final String packages = SystemProperties.get(PROP_PACKAGES, "");
        final String profile = SystemProperties.get(PROP_PROFILE, PROFILE_IDLE)
                .trim().toLowerCase(Locale.ROOT);
        final String intensity = SystemProperties.get(PROP_INTENSITY, "1.0");
        final String fingerprint = enabled + "\n" + packages + "\n" + profile + "\n" + intensity;

        if (fingerprint.equals(mConfigFingerprint)) {
            return;
        }
        mConfigFingerprint = fingerprint;

        mEnabled = isTrue(enabled) && isPackageAllowed(packages);
        mProfile = PROFILE_WALKING.equals(profile) ? PROFILE_WALKING : PROFILE_IDLE;
        mIntensity = parseIntensity(intensity);
        mStartTimestampNs = 0;
        mLastTimestampNs = 0;
        mNoise[0] = 0.0f;
        mNoise[1] = 0.0f;
        mNoise[2] = 0.0f;
    }

    private boolean isPackageAllowed(String packageList) {
        if (packageList == null || packageList.isEmpty() || mPackageName.isEmpty()) {
            return false;
        }
        for (String candidate : packageList.split(",")) {
            if (mPackageName.equals(candidate.trim())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTrue(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static float parseIntensity(String value) {
        try {
            return clamp(Float.parseFloat(value), 0.05f, 3.0f);
        } catch (NumberFormatException e) {
            return 1.0f;
        }
    }

    private void updateNoise(float dtSeconds) {
        for (int i = 0; i < mNoise.length; i++) {
            final float target = mRandom.nextFloat() * 2.0f - 1.0f;
            final float alpha = clamp(dtSeconds / (0.18f + i * 0.08f), 0.01f, 0.35f);
            mNoise[i] += (target - mNoise[i]) * alpha;
        }
    }

    private void writeAccelerometer(float[] values, float t, float activity, boolean walking,
            boolean uncalibrated) {
        if (values.length < 3) return;
        writeGravity(values, t, activity);
        final float gravityX = values[0];
        final float gravityY = values[1];
        final float gravityZ = values[2];
        writeLinearAcceleration(values, t, activity, walking);
        final float linearX = values[0];
        final float linearY = values[1];
        final float linearZ = values[2];

        values[0] = gravityX + linearX + mNoise[0] * 0.025f;
        values[1] = gravityY + linearY + mNoise[1] * 0.025f;
        values[2] = gravityZ + linearZ + mNoise[2] * 0.025f;
        if (uncalibrated && values.length >= 6) {
            values[3] = mNoise[0] * 0.006f;
            values[4] = mNoise[1] * 0.006f;
            values[5] = mNoise[2] * 0.006f;
        }
    }

    private void writeGravity(float[] values, float t, float activity) {
        if (values.length < 3) return;
        calculateAngles(t, activity, mAngles);
        final float roll = mAngles[0];
        final float pitch = mAngles[1];

        values[0] = -GRAVITY * (float) Math.sin(pitch);
        values[1] = GRAVITY * (float) Math.sin(roll) * (float) Math.cos(pitch);
        values[2] = GRAVITY * (float) Math.cos(roll) * (float) Math.cos(pitch);
    }

    private void writeLinearAcceleration(float[] values, float t, float activity,
            boolean walking) {
        if (values.length < 3) return;
        final float stride = walking ? 1.8f : 0.42f;
        final float amplitude = walking ? 0.85f : 0.035f;
        values[0] = amplitude * (float) Math.sin(stride * t + 0.4f)
                + mNoise[0] * amplitude * 0.08f;
        values[1] = amplitude * 0.55f * (float) Math.sin(stride * 1.31f * t + 1.2f)
                + mNoise[1] * amplitude * 0.08f;
        values[2] = amplitude * 0.75f * (float) Math.sin(stride * 2.0f * t + 0.7f)
                + mNoise[2] * amplitude * 0.08f;
    }

    private void writeGyroscope(float[] values, float t, float activity, boolean uncalibrated) {
        if (values.length < 3) return;
        calculateRates(t, activity, mRates);
        values[0] = mRates[0] + mNoise[0] * 0.0015f;
        values[1] = mRates[1] + mNoise[1] * 0.0015f;
        values[2] = mRates[2] + mNoise[2] * 0.0015f;
        if (uncalibrated && values.length >= 6) {
            values[3] = 0.0008f * mNoise[0];
            values[4] = 0.0008f * mNoise[1];
            values[5] = 0.0008f * mNoise[2];
        }
    }

    private void writeRotationVector(float[] values, float t, float activity) {
        if (values.length < 4) return;
        calculateAngles(t, activity, mAngles);
        final float halfRoll = mAngles[0] * 0.5f;
        final float halfPitch = mAngles[1] * 0.5f;
        final float halfYaw = mAngles[2] * 0.5f;
        final float cr = (float) Math.cos(halfRoll);
        final float sr = (float) Math.sin(halfRoll);
        final float cp = (float) Math.cos(halfPitch);
        final float sp = (float) Math.sin(halfPitch);
        final float cy = (float) Math.cos(halfYaw);
        final float sy = (float) Math.sin(halfYaw);

        values[0] = sr * cp * cy - cr * sp * sy;
        values[1] = cr * sp * cy + sr * cp * sy;
        values[2] = cr * cp * sy - sr * sp * cy;
        values[3] = cr * cp * cy + sr * sp * sy;
        if (values.length >= 5) {
            values[4] = 0.035f;
        }
    }

    private void writeOrientation(float[] values, float t, float activity) {
        if (values.length < 3) return;
        calculateAngles(t, activity, mAngles);
        values[0] = mAngles[2] / DEG_TO_RAD;
        values[1] = mAngles[1] / DEG_TO_RAD;
        values[2] = mAngles[0] / DEG_TO_RAD;
    }

    private void calculateAngles(float t, float activity, float[] out) {
        out[0] = activity * (0.018f * (float) Math.sin(0.37f * t + 0.9f)
                + 0.007f * (float) Math.sin(0.91f * t + 1.7f));
        out[1] = activity * (0.024f * (float) Math.sin(0.31f * t + 0.2f)
                + 0.006f * (float) Math.sin(1.13f * t + 2.1f));
        out[2] = activity * (0.021f * (float) Math.sin(0.43f * t + 2.0f)
                + 0.008f * (float) Math.sin(0.79f * t + 0.5f));
    }

    private void calculateRates(float t, float activity, float[] out) {
        out[0] = activity * (0.018f * 0.37f * (float) Math.cos(0.37f * t + 0.9f)
                + 0.007f * 0.91f * (float) Math.cos(0.91f * t + 1.7f));
        out[1] = activity * (0.024f * 0.31f * (float) Math.cos(0.31f * t + 0.2f)
                + 0.006f * 1.13f * (float) Math.cos(1.13f * t + 2.1f));
        out[2] = activity * (0.021f * 0.43f * (float) Math.cos(0.43f * t + 2.0f)
                + 0.008f * 0.79f * (float) Math.cos(0.79f * t + 0.5f));
    }

    private static float clamp(float value, float min, float max) {
        return Math.max(min, Math.min(max, value));
    }
}

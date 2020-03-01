package com.xin.biometricprompt.bio;

import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import androidx.annotation.RequiresApi;
import android.widget.Toast;

public class Biometric {

    @RequiresApi(api = 28)
    public static BiometricPrompt createPrompt(final Context context, String title, String subTitle, String desc) {
        return new BiometricPrompt.Builder(context)
                .setTitle(title)
                .setSubtitle(subTitle)
                .setDescription(desc)
                .setNegativeButton("取消", context.getMainExecutor(), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Toast.makeText(context, "注册取消", Toast.LENGTH_SHORT).show();
                    }
                })
                .build();
    }

    public static CancellationSignal createCancelSignal() {
        CancellationSignal signal = new CancellationSignal();
        signal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {

            }
        });
        return signal;
    }

    @RequiresApi(api = 28)
    public static boolean isSupportBiometric(Context context) {
        PackageManager manager = context.getPackageManager();
        return manager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);
    }
}

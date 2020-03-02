package com.xin.biometricprompt;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;

import java.util.Objects;


public class FpAuthUI extends DialogFragment {

    private TextView tvLeftTime;

    private CountDownTimer countDownTimer;

    private static final int TIME_COUNT_DOWN = 30;
    private static final String KEY_SAVE_INSTANCE_STATUS_LEFT_TIME = "LEFT_TIME";

    private int leftTime = TIME_COUNT_DOWN;

    //private boolean flag = false;

    private String msg = "";

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public FpAuthUI() {
        setRetainInstance(true);
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {

        if (savedInstanceState != null) {
            leftTime = savedInstanceState.getInt(KEY_SAVE_INSTANCE_STATUS_LEFT_TIME);
        }

        tvLeftTime = new TextView(getActivity());
        tvLeftTime.setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        tvLeftTime.setGravity(Gravity.CENTER);
        tvLeftTime.setText(String.valueOf(leftTime));


        countDownTimer = new CountDownTimer(leftTime * 1000, 1000) {
            @Override
            public void onTick(long millisUntilFinished) {

                if (TextUtils.isEmpty(msg)) {
                    leftTime -= 1;
                    tvLeftTime.setText(String.valueOf(leftTime));

                } else {
                    if (tvLeftTime.getText().toString().equals(msg)) {
                        dismiss();
                    }

                    tvLeftTime.setText(msg);
                }
            }

            @Override
            public void onFinish() {

                //leftTime = 30;


                dismiss();
            }
        };

        countDownTimer.start();


        return new AlertDialog.Builder(Objects.requireNonNull(getActivity()))
                .setTitle("指纹验证")
                .setView(tvLeftTime)
                .setNegativeButton("使用密码", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {

                    }
                })
                .create();

    }


    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);

        if (tvLeftTime != null)
            outState.putInt(KEY_SAVE_INSTANCE_STATUS_LEFT_TIME, Integer.parseInt(tvLeftTime.getText().toString()));

    }

    @Override
    public void onDismiss(@NonNull DialogInterface dialog) {
        super.onDismiss(dialog);

        if (countDownTimer != null) {
            countDownTimer.cancel();
        }

    }


}

package org.xdty.authenticator;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.CheckBox;
import android.widget.CompoundButton;

import org.xdty.authenticator.androidlockpattern.LockPatternActivity;
import org.xdty.authenticator.androidlockpattern.util.Settings;
import org.xdty.authenticator.security.LPEncrypter;

public class LockPatternSettingActivity extends Activity {

    private static final int REQ_CREATE_PATTERN = 1;
    private static final int REQ_ENTER_PATTERN = 2;
    private static final String TAG = "LockPatternSetting";

    private CheckBox enableLockPattern;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_lock_pattern);

        enableLockPattern = (CheckBox) findViewById(R.id.enable_lock_pattern);
        final CheckBox displayUnlockPattern = (CheckBox) findViewById(R.id.display_unlock_pattern);

        if (Settings.Security.getPattern(this) != null) {
            enableLockPattern.setChecked(true);
        }

        if (!Settings.Display.isStealthMode(this)) {
            displayUnlockPattern.setChecked(true);
        }

        enableLockPattern.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {

                if (isChecked) {
                    Settings.Security.setEncrypterClass(LockPatternSettingActivity.this, LPEncrypter.class);

                    Settings.Security.setAutoSavePattern(LockPatternSettingActivity.this, true);
                    Intent intent = new Intent(LockPatternActivity.ACTION_CREATE_PATTERN, null,
                            LockPatternSettingActivity.this, LockPatternActivity.class);
                    startActivityForResult(intent, REQ_CREATE_PATTERN);
                } else {
                    Settings.Security.setPattern(LockPatternSettingActivity.this, null);
                }
            }
        });

        displayUnlockPattern.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    Settings.Display.setStealthMode(LockPatternSettingActivity.this, false);
                } else {
                    Settings.Display.setStealthMode(LockPatternSettingActivity.this, true);
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode,
                                    Intent data) {
        switch (requestCode) {
            case REQ_CREATE_PATTERN:
                if (resultCode != RESULT_OK) {
                    enableLockPattern.setChecked(false);
                }
                break;

        }
    }
}

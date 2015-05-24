package com.google.android.apps.authenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.apps.authenticator.testability.DependencyInjector;
import com.google.android.apps.authenticator2.R;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ExportActivity extends Activity implements MediaScannerConnection.MediaScannerConnectionClient {

    public final static String TAG = "ExportActivity";
    private final static int PASSWORD_ITERATIONS = 65536;
    private final static int KEY_SIZE = 256;
    private final static int SALT_SIZE = 20;
    private final static int IV_SIZE = 16;
    private final static String AUTH_FILE = "Authenticator.key";
    private static String authPassword = "";
    private AccountDb mAccountDb;

    private MediaScannerConnection mMs;
    private File mFile;

    private ProgressDialog progress;
    private Handler handler;

    private AlertDialog importDialog;
    private AlertDialog exportDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_export);

        mAccountDb = DependencyInjector.getAccountDb();

        findViewById(R.id.export_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportDialog.show();
            }
        });

        findViewById(R.id.import_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importDialog.show();
            }
        });

        progress = new ProgressDialog(this);
        progress.setCancelable(false);
        handler = new Handler();

        LayoutInflater layoutInflater = LayoutInflater.from(this);

        final View exportView = layoutInflater.inflate(R.layout.export_dialog, null);
        Button positiveButton = (Button)exportView.findViewById(R.id.ok);
        Button negativeButton = (Button)exportView.findViewById(R.id.cancel);

        positiveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText password = (EditText) exportView.findViewById(R.id.password);
                EditText verify = (EditText) exportView.findViewById(R.id.password_verify);
                TextView error = (TextView) exportView.findViewById(R.id.password_error);

                if (password.getText().toString().equals(verify.getText().toString())) {
                    authPassword = password.getText().toString();

                    if (TextUtils.isEmpty(authPassword)) {
                        error.setText(R.string.password_empty);
                        error.setVisibility(View.VISIBLE);
                    } else {
                        password.setText("");
                        verify.setText("");
                        doExport();
                        exportDialog.dismiss();
                    }
                } else {
                    error.setText(R.string.passwrod_error);
                    error.setVisibility(View.VISIBLE);
                }
            }
        });

        negativeButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportDialog.dismiss();
            }
        });

        AlertDialog.Builder exportDialogBuilder = new AlertDialog.Builder(this);
        exportDialogBuilder.setView(exportView);

        exportDialog = exportDialogBuilder.create();

        final View importView = layoutInflater.inflate(R.layout.import_dialog, null);
        AlertDialog.Builder importDialogBuilder = new AlertDialog.Builder(this);
        importDialogBuilder
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        EditText password = (EditText) importView.findViewById(R.id.password);
                        authPassword = password.getText().toString();
                        password.setText("");
                        doImport();
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .setView(importView);

        importDialog = importDialogBuilder.create();
    }

    @Override
    protected void onDestroy() {

        if (importDialog != null) {
            importDialog.dismiss();
        }

        if (exportDialog != null) {
            exportDialog.dismiss();
        }

        if (progress != null) {
            progress.dismiss();
        }
        super.onDestroy();
    }

    private void doExport() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                showProcessDialog(true, getString(R.string.export_message));

                try {
                    exportKeys();
                    makeToast(getString(R.string.export_succeed));
                } catch (Exception e) {
                    makeToast(getString(R.string.export_failed));
                    e.printStackTrace();
                } finally {
                    showProcessDialog(false, "");
                }
            }
        }).start();
    }

    private void doImport() {
        new Thread(new Runnable() {
            @Override
            public void run() {

                showProcessDialog(true, getString(R.string.import_message));

                try {
                    importKeys();
                    makeToast(getString(R.string.import_succeed));
                } catch (Exception e) {
                    e.printStackTrace();
                    makeToast(getString(R.string.import_failed));
                } finally {
                    showProcessDialog(false, "");
                }
            }
        }).start();
    }

    private void showProcessDialog(final boolean isVisible, final String message) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                if (isVisible) {
                    progress.setMessage(message);
                    progress.show();
                } else {
                    progress.dismiss();
                }
            }
        });
    }

    private void makeToast(final String message) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(ExportActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void importKeys() throws Exception {
        File storage = Environment.getExternalStorageDirectory();
        File importFile = new File(storage, AUTH_FILE);
        FileInputStream fileInputStream = new FileInputStream(importFile);

        StringBuilder builder = new StringBuilder();
        int ch;
        while ((ch = fileInputStream.read()) != -1) {
            builder.append((char) ch);
        }

        fileInputStream.close();

        JSONObject jsonObject = new JSONObject(decrypt(builder.toString()));

        JSONArray jsonArray = jsonObject.getJSONArray("auth");

        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject object = jsonArray.getJSONObject(i);
            String user = object.getString("user");
            String secret = object.getString("secret");
            AccountDb.OtpType type = AccountDb.OtpType.valueOf(object.getString("type"));
            int counter = object.getInt("counter");

            AccountDb accountDb = DependencyInjector.getAccountDb();
            accountDb.update(user, secret, user, type, counter);
            DependencyInjector.getOptionalFeatures().onAuthenticatorActivityAccountSaved(this, user);
        }

    }

    private void exportKeys() throws Exception {

        ArrayList<String> userNames = new ArrayList<>();
        mAccountDb.getNames(userNames);

        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();

        for (String user : userNames) {
            JSONObject jsonUser = new JSONObject();
            jsonUser.put("user", user);
            jsonUser.put("secret", mAccountDb.getSecret(user));
            jsonUser.put("type", mAccountDb.getType(user));
            jsonUser.put("counter", mAccountDb.getCounter(user));
            jsonArray.put(jsonUser);
        }

        jsonObject.put("auth", jsonArray);

        File storage = Environment.getExternalStorageDirectory();

        File exportFile = new File(storage, AUTH_FILE);

        if (exportFile.exists()) {
            exportFile.delete();
        }

        FileOutputStream outputStream = new FileOutputStream(exportFile);
        outputStream.write(encrypt(jsonObject.toString()).getBytes());
        outputStream.close();

        mFile = exportFile;
        mMs = new MediaScannerConnection(this, this);
        mMs.connect();
    }

    @Override
    public void onMediaScannerConnected() {
        mMs.scanFile(mFile.getAbsolutePath(), null);
    }

    @Override
    public void onScanCompleted(String path, Uri uri) {
        mMs.disconnect();
    }

    public String decrypt(String encryptedText) throws Exception {

        byte[] saltBytes = new byte[SALT_SIZE];
        byte[] ivBytes = new byte[IV_SIZE];
        byte[] inBytes = Base64.decode(encryptedText, Base64.DEFAULT);

        byte[] encryptedTextBytes = new byte[inBytes.length - saltBytes.length - IV_SIZE];
        System.arraycopy(inBytes, 0, encryptedTextBytes, 0, encryptedTextBytes.length);
        System.arraycopy(inBytes, encryptedTextBytes.length, saltBytes, 0, saltBytes.length);
        System.arraycopy(inBytes, encryptedTextBytes.length + saltBytes.length, ivBytes, 0, IV_SIZE);

        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                authPassword.toCharArray(),
                saltBytes,
                PASSWORD_ITERATIONS,
                KEY_SIZE
        );

        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Decrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

        byte[] decryptedTextBytes = null;
        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return new String(decryptedTextBytes);
    }

    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[SALT_SIZE];
        random.nextBytes(bytes);
        return bytes;
    }

    public String encrypt(String plainText) throws Exception {

        //get salt
        byte[] saltBytes = generateSalt();

        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(
                authPassword.toCharArray(),
                saltBytes,
                PASSWORD_ITERATIONS,
                KEY_SIZE
        );

        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));

        byte[] outBytes = new byte[encryptedTextBytes.length + saltBytes.length + ivBytes.length];
        System.arraycopy(encryptedTextBytes, 0, outBytes, 0, encryptedTextBytes.length);
        System.arraycopy(saltBytes, 0, outBytes, encryptedTextBytes.length, saltBytes.length);
        System.arraycopy(ivBytes, 0, outBytes, encryptedTextBytes.length + saltBytes.length, ivBytes.length);

        return Base64.encodeToString(outBytes, Base64.DEFAULT);
    }

}

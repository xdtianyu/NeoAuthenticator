package com.google.android.apps.authenticator;

import android.app.Activity;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import com.google.android.apps.authenticator.testability.DependencyInjector;
import com.google.android.apps.authenticator2.R;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class ExportActivity extends Activity implements MediaScannerConnection.MediaScannerConnectionClient {

    public final static String TAG = "ExportActivity";

    private AccountDb mAccountDb;

    private MediaScannerConnection mMs;
    private File mFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_export);

        mAccountDb = DependencyInjector.getAccountDb();

        findViewById(R.id.export_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    exportKeys();
                    Toast.makeText(ExportActivity.this, "Exported succeed", Toast.LENGTH_SHORT).show();
                } catch (JSONException | IOException e) {
                    e.printStackTrace();
                    Toast.makeText(ExportActivity.this, "Exported error", Toast.LENGTH_SHORT).show();
                }
            }
        });

        findViewById(R.id.import_button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    importKeys();
                    Toast.makeText(ExportActivity.this, "Imported succeed", Toast.LENGTH_SHORT).show();
                } catch (JSONException | IOException e) {
                    Toast.makeText(ExportActivity.this, "Imported error", Toast.LENGTH_SHORT).show();
                    e.printStackTrace();
                }
            }
        });
    }

    private void importKeys() throws IOException, JSONException {
        File storage = Environment.getExternalStorageDirectory();
        File importFile = new File(storage, "export.json");
        FileInputStream fileInputStream = new FileInputStream(importFile);

        StringBuilder builder = new StringBuilder();
        int ch;
        while((ch = fileInputStream.read()) != -1){
            builder.append((char)ch);
        }

        fileInputStream.close();

        JSONObject jsonObject = new JSONObject(builder.toString());

        JSONArray jsonArray = jsonObject.getJSONArray("auth");

        for (int i=0; i<jsonArray.length(); i++) {
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

    private void exportKeys() throws JSONException, IOException {

        ArrayList<String> usernames = new ArrayList<>();
        mAccountDb.getNames(usernames);

        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();

        for (String user:usernames) {
            JSONObject jsonUser = new JSONObject();
            jsonUser.put("user", user);
            jsonUser.put("secret", mAccountDb.getSecret(user));
            jsonUser.put("type", mAccountDb.getType(user));
            jsonUser.put("counter", mAccountDb.getCounter(user));
            jsonArray.put(jsonUser);
        }

        jsonObject.put("auth", jsonArray);

        File storage = Environment.getExternalStorageDirectory();

        File exportFile = new File(storage, "export.json");

        if (exportFile.exists()) {
            exportFile.delete();
        }

        FileOutputStream outputStream = new FileOutputStream(exportFile);
        outputStream.write(jsonObject.toString().getBytes());
        outputStream.close();

        mFile = exportFile;
        mMs = new MediaScannerConnection(this, this);
        mMs.connect();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_export, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onMediaScannerConnected() {
        mMs.scanFile(mFile.getAbsolutePath(), null);
    }

    @Override
    public void onScanCompleted(String path, Uri uri) {
        mMs.disconnect();
    }
}

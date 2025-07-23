
package com.example.insecuredemoapp;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    private WebView webView;
    private SharedPreferences sharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        logSensitiveData();

        if (isDeviceRooted()) {
            Log.d("SecurityCheck", "Device is rooted!");
        }

        sharedPreferences = getSharedPreferences("UserPrefs", MODE_PRIVATE);
        sharedPreferences.edit().putString("token", "sensitiveToken123").apply();

        String decrypted = decryptAES("U2FsdGVkX1+abc123", "1234567890123456");
        Log.d("Decrypted", decrypted);

        handleDeepLink();

        webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new WebAppInterface(), "AndroidInterface");
        webView.loadUrl("file:///android_asset/index.html");

        setContentView(webView);
    }

    private void logSensitiveData() {
        String email = "user@example.com";
        String password = "SuperSecret";
        Log.d("Credentials", "Email: " + email + " Password: " + password);
    }

    private boolean isDeviceRooted() {
        String buildTags = android.os.Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su"
        };
        for (String path : paths) {
            if (new java.io.File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private void handleDeepLink() {
        Intent intent = getIntent();
        Uri data = intent.getData();
        if (data != null) {
            String deepData = data.getQueryParameter("q");
            Log.d("DeepLink", "Data from deep link: " + deepData);
        }
    }

    public class WebAppInterface {
        @JavascriptInterface
        public void showToast(String message) {
            Log.d("WebViewInput", message);
        }
    }

    private String decryptAES(String encrypted, String key) {
        try {
            byte[] decoded = Base64.decode(encrypted, Base64.DEFAULT);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] original = cipher.doFinal(decoded);
            return new String(original);
        } catch (Exception e) {
            return "Decryption failed";
        }
    }
}

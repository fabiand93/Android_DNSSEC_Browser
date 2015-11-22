package com.ennio.calderoni.dnssec_browser10;

import android.app.AlertDialog;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.StrictMode;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.io.IOException;



public class MainActivity extends ActionBarActivity {
    private WebSettings webSettings;
    private WebView myWebView;
    EditText myTxtURL;
    ImageButton button;
    Button secButton;
    ProgressBar progress;




    @Override
    protected void onCreate(Bundle savedInstanceState) {
        System.setProperty("sun.net.spi.nameservice.provider.1", "dns,dnsjava");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        progress = (ProgressBar) findViewById(R.id.progressBar);
        secButton = (Button) findViewById(R.id.security);
        myWebView = (WebView) findViewById(R.id.webview);
        myTxtURL = (EditText) findViewById(R.id.url);
        webSettings = myWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setBuiltInZoomControls(true);
        myWebView.setWebViewClient(new Browser(this, secButton, progress, myTxtURL));
        myWebView.loadUrl("http://www.google.com");
        button = (ImageButton) findViewById(R.id.search_go_btn);
        button.requestFocus();

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();

        StrictMode.setThreadPolicy(policy);

        if (!isNetworkAvailable()){
            AlertDialog.Builder builder=new AlertDialog.Builder(this);
            builder.setTitle("No Internet Connection");
            builder.setMessage("Connect the Device to Internet");
            builder.show();
        }




        myTxtURL.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if ((event != null && (event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) || (actionId == EditorInfo.IME_ACTION_DONE)) {
                    EditText url = (EditText) findViewById(R.id.url);
                    final String urlToValidate = url.getText().toString();

                    passUrl(urlToValidate);


                }
                return false;
            }
        });



    }


    @Override
    public void onBackPressed() {
        if (myWebView.canGoBack()) {
            Log.d("CDA", "onBackPressed Called");
            myWebView.goBack();
            myTxtURL.setText(myWebView.getOriginalUrl());
            secButton.setBackgroundColor(Color.GRAY);
            secButton.setClickable(false);

        } else {
            super.onBackPressed();
        }
    }


    public void search(View v) throws IOException {

        if (!isNetworkAvailable()){
            AlertDialog.Builder builder=new AlertDialog.Builder(this);
            builder.setTitle("No Internet Connection");
            builder.setMessage("Connect the Device to Internet");
            builder.show();
        }

        EditText url = (EditText) findViewById(R.id.url);
        final String urlToValidate = url.getText().toString();
        if (!urlToValidate.isEmpty()) {
            passUrl(urlToValidate);
        }


    }

    public void passUrl(String urlToValidate) {

        secButton.setTextColor(Color.GRAY);
        secButton.setClickable(true);
        Browser b = new Browser(this, secButton, progress, myTxtURL);
        boolean rogue=false;
        progress.setVisibility(View.VISIBLE);
        urlToValidate = urlToValidate.replace("https://", "");
        urlToValidate = urlToValidate.replace("http://", "");

        myWebView.loadUrl("http://" + urlToValidate);
        int colorId = secButton.getCurrentTextColor();
        if (colorId==-7829368) {
            try {
                if(urlToValidate.contains("/")) {
                    urlToValidate = urlToValidate.substring(0, urlToValidate.indexOf("/") - 1);
                }
                rogue = b.validator(urlToValidate + ".", myWebView);
            } catch (IOException e) {
                System.out.println("validator :" + e);
            }

            if (rogue) {
                myWebView.loadUrl("file:///android_asset/stop.html");
            }
        }

    }

    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager
                = (ConnectivityManager) getSystemService(this.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public void dnssecInfo(View v) {
       int colorId = secButton.getCurrentTextColor();

        AlertDialog.Builder builder=new AlertDialog.Builder(this);

        if (colorId==-65536) {
            builder.setTitle("Rogue Domain Name");
            builder.setMessage(" The Domain Name has an Invalid Domain Name Signature");
        }
        else
        if (colorId==-256) {
            builder.setTitle("The Domain Name is Insecure");
            builder.setMessage(" The Domain Name don't uses the Security extension of DNS");
        }
        else if (colorId==-16711936) {
            builder.setTitle("The Domain Name is Secure");
            builder.setMessage(" the Domain Name is Validated by DNSSEC ");
        }


        builder.show();
    }




}
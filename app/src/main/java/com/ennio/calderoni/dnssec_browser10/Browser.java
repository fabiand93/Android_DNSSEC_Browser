package com.ennio.calderoni.dnssec_browser10;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;

import org.jitsi.dnssec.validator.ValidatingResolver;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.UnknownHostException;


/**
 * Created by oinne on 11/9/15.
 */
public class Browser extends WebViewClient {



   static Context mContext;
    Button secButton;
    ProgressBar progress;
    EditText myTxtURL;


    /** Instantiate the interface and set the context */
    Browser(Context c, Button b, ProgressBar p, EditText e) {
        mContext = c;
        secButton =b;
        progress =p;
        myTxtURL =e;

    }


   static String ROOT = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (!url.isEmpty()) {
            progress.setVisibility(View.VISIBLE);

            String urlToCheck = Uri.parse(url).getHost();
            urlToCheck = urlToCheck.replace("https://", "");
            urlToCheck = urlToCheck.replace("http://", "");
            myTxtURL.setText(urlToCheck);
            if (urlToCheck.contains("/")) {
                urlToCheck = url.substring(0, urlToCheck.indexOf("/") - 1);
            }

            try {
                validator(urlToCheck + ".", view);
            } catch (IOException e) {
                System.out.println("validator :" + e);

            }

        }

            return false;
    }

    @Override
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        // TODO Auto-generated method stub
        super.onPageStarted(view, url, favicon);
    }

    public void onPageFinished(WebView view, String url) {
        // TODO Auto-generated method stub
        super.onPageFinished(view, url);

        progress.setVisibility(View.GONE);
    }




    public boolean validator( String url, WebView view) throws IOException {

        secButton.setClickable(true);

        boolean rogue=false;
        SimpleResolver sr = null;
        try {
            sr = new SimpleResolver("8.8.8.8");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        assert sr != null;
        ValidatingResolver vr = new ValidatingResolver(sr);
        try {
            vr.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes("ASCII")));
        } catch (IOException e) {
            System.out.println("loadTrustAnchors :" + e);
        }
        Record qr = Record.newRecord(Name.fromConstantString(url), Type.A, DClass.IN);
        Message response = vr.send(Message.newQuery(qr));
        String reasons="";
        for (RRset set : response.getSectionRRsets(Section.ADDITIONAL)) {
            if (set.getName().equals(Name.root) && set.getType() == Type.TXT
                    && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                reasons =reasons+" \n"+((TXTRecord) set.first()).getStrings().get(0).toString();


            }
        }

          if (!reasons.isEmpty()) {
            if (reasons.contains("Could not establish a chain of trust to keys for")) {
                secButton.setBackgroundColor(Color.RED);
                secButton.setTextColor(Color.RED);
                view.loadUrl("file:///android_asset/stop.html");
                rogue=true;
            }

            else {
                secButton.setBackgroundColor(Color.YELLOW);
                secButton.setTextColor(Color.YELLOW);
            }

        }
        else {
            secButton.setBackgroundColor(Color.GREEN);
            secButton.setTextColor(Color.GREEN);
        }



        return rogue;


    }





}

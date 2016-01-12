package com.ennio.calderoni.dnssec_browser10;

import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.net.http.SslError;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.util.Log;
import android.view.View;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import org.apache.http.conn.util.InetAddressUtils;
import org.jitsi.dnssec.validator.ValidatingResolver;
import org.xbill.DNS.Address;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;




/**
 * Created by Ennio Calderoni on 11/9/15.
 */
/*this class contains the functions needed for the validation of domains*/
public class Browser extends WebViewClient {



   static Context mContext;
    Button secButton;
    ProgressBar progress;
    EditText myTxtURL;


    /** Instantiate the interface and set the context */
    Browser(Context c, Button b, ProgressBar p, EditText e) {
        mContext = c;
        secButton = b;
        progress = p;
        myTxtURL = e;

    }


   static String ROOT = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"; // the root anchor yoused to validate the DNSSEC keys

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        myTxtURL.setText(url);
       /* if (!url.contains("https://")){
            AlertDialog.Builder builder=new AlertDialog.Builder(mContext);
            builder.setTitle("No HTTPS Connection");
            builder.setMessage("the data exchanged with the website are not encrypted ");
            builder.show();
        }*/
        if (!url.isEmpty()) {
            progress.setVisibility(View.VISIBLE);

            String urlToCheck = Uri.parse(url).getHost();
            urlToCheck = cleaning(urlToCheck);

            try {
                validator(urlToCheck + ".", view);
            } catch (IOException e) {
                System.out.println("validator :" + e);

            }

        }
            return false;
    }

    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
         // says there is something wrong with ssl certificate
        AlertDialog.Builder builder=new AlertDialog.Builder(mContext);
        handler.cancel();
        builder.setTitle("This Connection is Untrusted");
        builder.setMessage(" The Connection with the URL have been stopped for security reasons ");
        builder.show();
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

    public String cleaning (String urlToCheck){

        //myTxtURL.setText(urlToCheck);
        urlToCheck = urlToCheck.replace("https://", "");
        urlToCheck = urlToCheck.replace("http://", "");

        if (urlToCheck.startsWith("/")) {
            urlToCheck = urlToCheck.substring(1, urlToCheck.length());
        }

        if (urlToCheck.contains("/")) {
            urlToCheck = urlToCheck.substring(0, urlToCheck.indexOf("/"));
        }


        if (urlToCheck.endsWith(".")){
            urlToCheck = urlToCheck.substring(0, urlToCheck.length()-1);
        }

        if (urlToCheck.startsWith(".")){
            urlToCheck = urlToCheck.substring(1, urlToCheck.length());
        }

        return urlToCheck;
    }

    public boolean isIp(String url){

        String ip= url.substring(0, url.length() - 1);
        boolean isIp4 = InetAddressUtils.isIPv4Address(ip);
        boolean isIp6 = InetAddressUtils.isIPv6Address(ip);

        return isIp4 | isIp6;
    }

    public boolean isEqualIp(String url, ValidatingResolver vr, int method, SimpleResolver sr) throws IOException {
/* this function checks if the url is an ip*/
        // better change the contain with equal
        //check for A results with google DNS

        String stringSection = null;
        Record qr = Record.newRecord(Name.fromConstantString(url), Type.A, DClass.IN);
        Message response = vr.send(Message.newQuery(qr));
        stringSection = "" + response.sectionToString(1);

        //check for A results with the local DNS
        InetAddress addr = Address.getByName(url);
        String addr1 = addr.toString();
        addr1 = addr1.substring(addr1.indexOf("/") + 1);

        // method is 1 if the domain is protected with DNSSEC else if not
         if (method == 1) {
            return stringSection.contains(addr1);
        }
        else {

            if (stringSection.contains(addr1))
                return true;
            else {

                Lookup lookup = new Lookup(url, Type.NS);
                lookup.setResolver(sr);
                lookup.run();
                String ns = "";
                if (lookup.getResult() == Lookup.SUCCESSFUL) {
                    for (Record record : lookup.getAnswers()) {
                        ns = record.toString();
                    }


                    String[] lines = ns.split(System.getProperty("line.separator"));

                    ns = lines[0].substring(lines[0].indexOf("NS") + 3);


                    stringSection = null;
                    qr = Record.newRecord(Name.fromConstantString(ns), Type.A, DClass.IN);
                  //  long startTime = System.currentTimeMillis();
                    response = vr.send(Message.newQuery(qr));
                  //  long finishTime = System.currentTimeMillis();
                  //  long elapsedTime = startTime - finishTime;
                    stringSection = "" + response.sectionToString(1);



                    addr = Address.getByName(ns);
                    addr1 = addr.toString();
                    addr1 = addr1.substring(addr1.indexOf("/") + 1);

                    return stringSection.contains(addr1);


                } else {
                    String parent = url.substring(url.indexOf(".") + 1);
                    Lookup lookup1 = new Lookup(parent, Type.NS);
                    lookup1.setResolver(sr);
                    lookup1.run();
                    String ns1 = "";
                    if (lookup1.getResult() == Lookup.SUCCESSFUL) {
                        for (Record record : lookup1.getAnswers()) {
                            ns1 = record.toString();
                        }


                        String[] lines = ns1.split(System.getProperty("line.separator"));

                        ns1 = lines[0].substring(lines[0].indexOf("NS") + 3);


                        stringSection = null;
                        qr = Record.newRecord(Name.fromConstantString(ns1), Type.A, DClass.IN);
                        response = vr.send(Message.newQuery(qr));
                        stringSection = "" + response.sectionToString(1);


                        addr = Address.getByName(ns1);
                        addr1 = addr.toString();
                        addr1 = addr1.substring(addr1.indexOf("/") + 1);

                        return stringSection.contains(addr1.toString());

                    }


                }



            }
        }
        return false;
    }

    /*the  function validator puts together all the other functions to validate a domain with DNSSEC or to detect an hijacking attack*/

    public boolean validator( String url, WebView view) throws IOException {

        secButton.setClickable(true);

        boolean rogue = false;
        SimpleResolver sr = null;

        try {
            sr = new SimpleResolver("8.8.8.8"); //google dns
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        assert sr != null;
        ValidatingResolver vr = new ValidatingResolver(sr);
        vr.setTimeout(10);
        try {
            vr.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes("ASCII")));
        } catch (IOException e) {
            System.out.println("loadTrustAnchors :" + e);
        }

        WifiManager wifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE) ;
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        String wifi = wifiInfo.getSSID();
        Boolean hijacking= false;


        Record qr = Record.newRecord(Name.fromConstantString(url), Type.A, DClass.IN);
        long startTime = System.currentTimeMillis();
        Message response = vr.send(Message.newQuery(qr));
        long finishTime = System.currentTimeMillis();
        long elapsedTime = finishTime-startTime;
        if (elapsedTime >= 9000) {
            view.loadUrl("file:///android_asset/exceded.html");
            return false;
        }



        boolean equal = false;
        String adFlag = "" + response.getHeader().getFlag(Flags.AD);
        String RCode = Rcode.string(response.getRcode());


        if (!isIp(url)) {

            if (!wifi.contains("unknow ssid")&&url!=null){


                String addr1 =null;
                String addr2= null;
                InetAddress addr = null;
                try {
                    addr = Address.getByName(url);
                    addr1 = addr.toString();
                    addr1 = addr1.substring(addr1.indexOf("/") + 1);
                    addr2 = addr1.substring(0, 3);
                    if (addr2.equals("10.")) {
                        hijacking = true;
                    } else if (addr2.equals("172")) {
                        addr2 = addr1.substring(3, 7);
                        if (15 < Integer.parseInt(addr2) && Integer.parseInt(addr2) < 32)

                        hijacking = true;
                    } else {
                        addr2 = addr1.substring(0, 7);
                        if (addr2.equals("192.168")) {
                            hijacking = true;
                        }
                    }
                }
                catch (Exception e) {
                    Log.w("errore", "nessun ip");
                }


            }


            if (hijacking){
                secButton.setBackgroundColor(Color.RED);
                secButton.setTextColor(Color.RED);
                view.loadUrl("file:///android_asset/stop2.html");
                return false;

            } else if (adFlag.contains("true") && RCode.contains("NOERROR")) {
                equal = isEqualIp(url, vr, 1, sr);
                if (equal) {
                    secButton.setBackgroundColor(Color.GREEN);
                    secButton.setTextColor(Color.GREEN);
                } else {
                    secButton.setBackgroundColor(Color.RED);
                    secButton.setTextColor(Color.RED);
                    view.loadUrl("file:///android_asset/stop2.html");

                }
            } else if (adFlag.contains("false") && RCode.contains("NOERROR")) {
                equal = isEqualIp(url, vr, 2, sr);
                if (equal) {
                    secButton.setBackgroundColor(Color.YELLOW);
                    secButton.setTextColor(Color.YELLOW);
                } else {
                    secButton.setBackgroundColor(Color.RED);
                    secButton.setTextColor(Color.RED);
                    view.loadUrl("file:///android_asset/stop2.html");
                }
            } else if (adFlag.contains("false") && RCode.contains("SERVFAIL")) {
                secButton.setBackgroundColor(Color.RED);
                secButton.setTextColor(Color.RED);
                view.loadUrl("file:///android_asset/stop.html");
                rogue = false;
            }

        } else {
            secButton.setBackgroundColor(Color.GRAY);
            secButton.setTextColor(Color.GRAY);
        }

        return rogue;

    }


}

package de.mopsdom.nslookup;

import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONObject;
import org.minidns.DnsClient;
import org.minidns.dnsserverlookup.DnsServerLookupMechanism;
import org.minidns.hla.ResolverApi;
import org.minidns.hla.ResolverResult;
import org.minidns.hla.SrvResolverResult;
import org.minidns.record.A;
import org.minidns.record.AAAA;
import org.minidns.record.CNAME;
import org.minidns.record.InternetAddressRR;
import org.minidns.record.MX;
import org.minidns.record.NS;
import org.minidns.record.PTR;
import org.minidns.record.SOA;
import org.minidns.record.TXT;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class nslookup extends CordovaPlugin {

  private void resolve(final JSONArray data, final CallbackContext callbackContext) {

    if (data == null || data.length() == 0) {
      callbackContext.error("bad request (parameter)");
      return;
    }

    JSONArray resultArray = new JSONArray();

    for (int n = 0; n < data.length(); n++) {
      String domain = "";
      String type = "";
      String useFallbackDns = "";
      ArrayList<String> dnsServers = new ArrayList<String>();
      try {
        JSONObject obj = data.optJSONObject(n);
        domain = obj.optString("query");
        type = obj.optString("type");
        useFallbackDns = obj.optString("useFallbackDns");

        for(int i = 0; i < obj.getJSONArray("dnsserver").length(); i++){
          dnsServers.add(obj.getJSONArray("dnsserver").getString(i));
        }
      } catch (Exception err) {
        useFallbackDns = "true";
        type = "A";
        try {
          domain = data.getString(n);
        } catch (Exception e) {}
      }
      JSONObject result = null;
      if (type.trim().length()==0)
      {
        type = "A";
      }

      result = doNslookup(domain, type, dnsServers, useFallbackDns.equalsIgnoreCase("true")||useFallbackDns.equalsIgnoreCase("1"));

      if (result != null) {
        resultArray.put(result);
      }
    }
    callbackContext.success(resultArray);
  }

  private ResolverApi getApi(ArrayList<String> dnsServers, boolean useFallback) {
    DnsClient client = new DnsClient();

    DnsServerLookupMechanism dnsServerLookup = new DnsServerLookupMechanism(){

      @Override
      public int compareTo(DnsServerLookupMechanism o) {
        return 0;
      }

      @Override
      public String getName() {
        return "CUSTOM_DNS_SERVER";
      }

      @Override
      public int getPriority() {
        return 0;
      }

      @Override
      public boolean isAvailable() {
        return true;
      }

      @Override
      public List<String> getDnsServerAddresses() {
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(dnsServers);
        return list;
      }
    };
    client.addDnsServerLookupMechanism(dnsServerLookup);

    client.setUseHardcodedDnsServers(useFallback);

    ResolverApi api = new ResolverApi(client);
    return api;
  }

  public JSONObject doNslookup(String query, String type,ArrayList<String> dnsServers, boolean useFallback) {

    Log.i("cordova-plugin-nslookup", "doNslookup");
    Log.i("cordova-plugin-nslookup", query);

    JSONObject r = new JSONObject();
    JSONArray recordArray = new JSONArray();

    JSONObject request = new JSONObject();
    JSONObject responseJson = new JSONObject();

    try {
      request.put("query", query);
      request.put("type", type);
    } catch (Exception e) {

    }

    try {
      if (query.trim().length() > 0) {
        if (type.equalsIgnoreCase("a") || type.equalsIgnoreCase("aaaa")) {

          ResolverResult result;

          if (type.equalsIgnoreCase("a")) {
            result = getApi(dnsServers,useFallback).resolve(query, A.class);
          } else {
            result = getApi(dnsServers,useFallback).resolve(query, AAAA.class);
          }

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set answers = result.getAnswers();
            for (Object itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", type.equalsIgnoreCase("a") ? "A" : "AAAA");
              obj.put("address", itm.toString());
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }

          responseJson.put("result", recordArray);
          r.put("request", request);
          r.put("response", responseJson);

        } else if (type.equalsIgnoreCase("cname")) {
          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, CNAME.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<CNAME> answers = result.getAnswers();
            for (CNAME itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", "CNAME");
              obj.put("target", itm.getTarget());
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }

        } else if (type.equalsIgnoreCase("mx")) {

          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, MX.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<MX> answers = result.getAnswers();
            for (MX itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", "MX");
              obj.put("target", itm.target.toString());
              obj.put("priority", itm.priority);
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }
        } else if (type.equalsIgnoreCase("NS")) {

          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, NS.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<NS> answers = result.getAnswers();
            for (NS itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", "NS");
              obj.put("target", itm.getTarget());
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }


        } else if (type.equalsIgnoreCase("PTR")) {

          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, PTR.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<PTR> answers = result.getAnswers();
            for (PTR itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", "PTR");
              obj.put("target", itm.getTarget());
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }

        } else if (type.equalsIgnoreCase("SOA")) {

          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, SOA.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<SOA> answers = result.getAnswers();
            for (SOA itm : answers) {
              JSONObject obj = new JSONObject();
              obj.put("type", "SOA");
              obj.put("host", itm.mname);
              obj.put("admin", itm.rname);
              obj.put("serial", itm.serial);
              obj.put("refresh", itm.refresh);
              obj.put("retry", itm.retry);
              obj.put("expire", itm.expire);
              obj.put("minimum", itm.minimum);
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }
        } else if (type.equalsIgnoreCase("SRV")) {

          SrvResolverResult result = getApi(dnsServers,useFallback).resolveSrv(query);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          }
          else
          {
            List<SrvResolverResult.ResolvedSrvRecord> srvRecords = result.getSortedSrvResolvedAddresses();
            // Loop over the domain names pointed by the SRV RR. MiniDNS will return the list
            // correctly sorted by the priority and weight of the related SRV RR.
            for (SrvResolverResult.ResolvedSrvRecord srvRecord : srvRecords) {
              // Loop over the Internet Address RRs resolved for the SRV RR. The order of
              // the list depends on the prefered IP version setting of MiniDNS.
              for (InternetAddressRR inetAddressRR : srvRecord.addresses) {
                InetAddress inetAddress = inetAddressRR.getInetAddress();

                JSONObject obj = new JSONObject();
                obj.put("type", "SRV");
                obj.put("address",inetAddress instanceof Inet6Address ? "["+inetAddress.getHostAddress()+"]":inetAddress.getHostAddress());
                obj.put("target", srvRecord.srv.target);
                obj.put("port", srvRecord.port);
                responseJson.put("status", "success");
                recordArray.put(obj);
              }
            }
          }
        } else if (type.equalsIgnoreCase("TXT")) {

          ResolverResult result = getApi(dnsServers,useFallback).resolve(query, TXT.class);

          if (!result.wasSuccessful()) {
            responseJson.put("status", "failed");
          } else {

            Set<TXT> answers = result.getAnswers();
            for (TXT itm : answers) {

              JSONObject obj = new JSONObject();
              obj.put("type", "TXT");
              obj.put("strings", itm.getText());
              responseJson.put("status", "success");
              recordArray.put(obj);
            }
          }
        }
        responseJson.put("result", recordArray);
      } else {
        responseJson.put("status", "failed");
      }
      r.put("request", request);
      r.put("response", responseJson);

    } catch (Exception e) {
      Log.e("cordova-plugin-nslookup", e != null ? e.getMessage() : "UNKNOWN ERROR");
      try {
        responseJson.put("status", "failed");
        responseJson.put("error", e != null ? e.getMessage() : "UNKNOWN ERROR");
        r.put("request", request);
        r.put("response", responseJson);
      }
      catch (Exception ex)
      {
      }
    }

    return r;
  }

  @Override
  public boolean execute(final String action, final JSONArray data, final CallbackContext callbackContext) {

    if (action.equals("resolve")) {

      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          resolve(data, callbackContext);
        }
      });

      return true;
    }

    return false;
  }
}

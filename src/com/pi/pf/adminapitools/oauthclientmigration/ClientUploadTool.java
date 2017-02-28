package com.pi.pf.adminapitools.oauthclientmigration;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ClientUploadTool {

	public ClientUploadTool(String inputFile, String pfHost, String pfPort, String pfAdmin, String pfPassword) throws JsonProcessingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		JsonNode clientList = mapper.readTree(new File(inputFile));
		JsonNode itemNodes = clientList.get("items");
		Iterator<JsonNode> iterator = itemNodes.elements();

		while (iterator.hasNext()) {
			JsonNode client = iterator.next();
			System.out.println(client.toString());
			doPost(String.format("https://%s:%s/pf-admin-api/v1/oauth/clients",pfHost,pfPort), client.toString(), pfAdmin, pfPassword);
		}
	}

	public static void main(String[] args) throws JsonProcessingException, IOException {
		Options options = buildOptions();
		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);
			new ClientUploadTool(cmd.getOptionValue("f"), cmd.getOptionValue("h"), cmd.getOptionValue("p"), cmd.getOptionValue("u"), cmd.getOptionValue("w"));
		} catch (ParseException e) {
			System.out.println (e.getMessage() + "\n");
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "ClientUploadTool", options );
		}
	}

	private static Options buildOptions() {
		Options options = new Options();
		options.addOption(Option.builder ("f").desc("Input json file").hasArg().required().build());
		options.addOption(Option.builder ("h").desc("PingFederate host").hasArg().required().build());
		options.addOption(Option.builder ("p").desc("PingFederate admin port").hasArg().required().build());
		options.addOption(Option.builder ("u").desc("PingFederate admin user").hasArg().required().build());
		options.addOption(Option.builder ("w").desc("PingFederate admin user password").hasArg().required().build());
		return options;
	}

	public void doPost(String url, String postBody, String user, String password) throws MalformedURLException, ProtocolException, IOException {

		HttpsURLConnection httpsURLConnection = getConnectionForMethod(url, "POST", user, password);
		httpsURLConnection.connect();
		System.out.println("POSTing data: " + url + " " + postBody);
		DataOutputStream postData = new DataOutputStream(httpsURLConnection.getOutputStream());
		postData.writeBytes(postBody);
		postData.flush();
		postData.close();

		int responseCode = httpsURLConnection.getResponseCode();
		System.out.println("Got response code: " + responseCode);
		httpsURLConnection.disconnect();
	}

	private HttpsURLConnection getConnectionForMethod(String postUrl, String method, String user, String password) throws MalformedURLException, IOException,
			ProtocolException {
		trustAllHosts();
		URL url = new URL(postUrl);

		HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();

		// TODO: DEV ONLY! Remove before deploying in production
		httpsURLConnection.setHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		});

		String user_pass = user + ":" + password;
		String encoded = Base64.encodeBase64String(user_pass.getBytes());
		httpsURLConnection.setRequestProperty("Authorization", "Basic " + encoded);
		httpsURLConnection.setRequestProperty("X-XSRF-Header", "Pingfederate");
		httpsURLConnection.setRequestProperty("Content-Type", "application/json");

		httpsURLConnection.setRequestMethod(method);
		httpsURLConnection.setUseCaches(false);
		httpsURLConnection.setDoInput(true);

		httpsURLConnection.setDoOutput(true);
		return httpsURLConnection;
	}

	// TODO: DEV ONLY! Remove before deploying in production
	private static void trustAllHosts() {
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[] {};
			}
		} };

		// Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

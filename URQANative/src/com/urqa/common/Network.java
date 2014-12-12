package com.urqa.common;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;

import android.util.Log;

public class Network extends Thread {

	public enum Method {
		GET, POST
	}

	private String mURL;
	private String data;
	private Method method;
	private boolean isEncrypt;

	
	public void setNetworkOption(String mURL, String data, Method method, boolean isEncrypt) {
		this.mURL = mURL;
		this.data = data;
		this.method = method;
		this.isEncrypt = isEncrypt;
	}

	public void onNetworkEnd(HttpResponse responseGet, HttpEntity resEntity) {

	}
	
	@Override
	public void run() {
		switch (method) {
		case GET:
			sendGetMethod();
			break;
		case POST:
			sendPostMethod();
			break;
		}
	}

	private void sendGetMethod() {
		try {
			HttpClient client = new DefaultHttpClient();
			setHttpParams(client.getParams());

			HttpGet get = new HttpGet(mURL);
			HttpResponse responseGet = client.execute(get);
			HttpEntity resEntityGet = responseGet.getEntity();

			onNetworkEnd(responseGet, resEntityGet);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void sendPostMethod() {
		try {
			HttpClient client = new DefaultHttpClient();
			setHttpParams(client.getParams());

			HttpPost post = new HttpPost(mURL);

			post.setHeader("Content-Type", "application/json; charset=utf-8");
			post.addHeader("version", "1.0.0");

			if (isEncrypt) {
				post.addHeader("Urqa-Encrypt-Opt","aes-256-cbc-pkcs5padding+base64");
				data = Encrytor.encrypt(data);
			}

			StringEntity input = new StringEntity(data, "UTF-8");

			post.setEntity(input);
			HttpResponse responsePOST = client.execute(post);
			HttpEntity resEntity = responsePOST.getEntity();

			int code = responsePOST.getStatusLine().getStatusCode();

			Log.i("UrQA", String.format("UrQA Response Code : %d", code));

			onNetworkEnd(responsePOST, resEntity);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void setHttpParams(HttpParams params) {
		params.setParameter("http.protocol.expect-continue", false);
		params.setParameter("http.connection.timeout", 5000);
		params.setParameter("http.socket.timeout", 5000);
	}



}

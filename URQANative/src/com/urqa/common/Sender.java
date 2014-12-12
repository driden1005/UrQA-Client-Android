package com.urqa.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.json.JSONException;
import org.json.JSONObject;

import android.util.Base64;

import com.urqa.Collector.ErrorReport;
import com.urqa.library.model.Authentication;

public class Sender {
	
	public static final String EXCEPTION_URL = StateData.ServerAddress + "client/send/exception/";
	public static final String NATIVE_EXCEPTION_URL = StateData.ServerAddress + "client/send/exception/native";
	public static final String SESSION_URL = StateData.ServerAddress + "client/connect";
	

	public static void sendSession(Authentication auth, String url)
			 {

		Network network = new Network();
		network.setNetworkOption(url, auth.toJSONObject().toString(),
				Network.Method.POST, true);
		network.start();
	}

	public static void sendErrors(ErrorReport report, String url)
			throws JSONException {

		Network network = new Network();
		network.setNetworkOption(url, makeJsonStr(report),
				Network.Method.POST, true);
		network.start();

//		try {
//			network.join();
//		} catch (InterruptedException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}

	public static void sendErrorsWithNative(ErrorReport report, String url,
			String fileName) {
		try {
			Network network = new Network();
			// # step 1 : init for reading
			FileInputStream fis = new FileInputStream(fileName);
			File dmp_file = new File(fileName);
			byte[] byteArr = new byte[(int) dmp_file.length()];

			// # step 2 : read file from image
			fis.read(byteArr);
			fis.close();

			// # step 3 : image to String using Base64
			report.NativeData = Base64.encodeToString(byteArr, Base64.NO_WRAP);

			// # step 4 : send data
			dmp_file.delete();
			network.setNetworkOption(url, makeJsonStrForNative(report),
					Network.Method.POST, true);
			network.start();

//			try {
//				network.join();
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static String makeJsonStr(ErrorReport data) throws JSONException {

		JSONObject object = new JSONObject();
		object.put("console_log", getLog(data));
		object.put("exception", data.ErrorData.toJSONObject());
		object.put("instance", getId(data));
		object.put("version", data.mUrQAVersion);
		return object.toString();

	}

	private static String makeJsonStrForNative(ErrorReport data)
			throws JSONException {

		JSONObject object = new JSONObject();
		object.put("console_log", getLog(data));
		object.put("exception", data.ErrorData.toJSONObject());
		object.put("instance", getId(data));
		object.put("version", data.mUrQAVersion);
		object.put("dump_data", data.NativeData);
		return object.toString();
	}

	private static JSONObject getLog(ErrorReport data) throws JSONException {
		JSONObject map = new JSONObject();
		map.put("data", data.LogData);
		return map;
	}

	private static JSONObject getId(ErrorReport data) throws JSONException {
		JSONObject map = new JSONObject();
		map.put("id", data.mId);
		return map;
	}

}

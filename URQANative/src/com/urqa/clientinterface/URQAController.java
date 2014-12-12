package com.urqa.clientinterface;



import java.io.File;
import java.io.IOException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.urqa.Collector.DeviceCollector;
import com.urqa.Collector.ErrorReport;
import com.urqa.Collector.ErrorReportFactory;
import com.urqa.common.Network;
import com.urqa.common.Encryptor;
import com.urqa.common.Encryptor.KeyStore;
import com.urqa.common.Sender;
import com.urqa.common.StateData;
import com.urqa.eventpath.EventPathManager;
import com.urqa.library.UncaughtExceptionHandler;
import com.urqa.library.model.Authentication;
import com.urqa.rank.ErrorRank;

public final class URQAController {



	public static void leaveBreadcrumb() {
		EventPathManager.CreateEventPath(2, "");
	}

	public static void leaveBreadcrumb(String tag) {
		/*
		 * 언제 데이터가 나가는건지 ?
		 */
		EventPathManager.CreateEventPath(2, tag);
	}
//(StateData.ServerAddress + url
	public static int NativeCrashCallback(String fileName) {
		ErrorReport report = ErrorReportFactory.CreateNativeErrorReport(StateData.AppContext);
		Sender.sendExceptionWithNative(report, Sender.NATIVE_EXCEPTION_URL, fileName);
		return 0;
	}
	
	public static void resetTokens(Context context) throws Exception {
		
		SharedPreferences prefs = context.getSharedPreferences(Encryptor.ENCRYPTION, Context.MODE_PRIVATE);
		SharedPreferences.Editor editor = prefs.edit();
		
		KeyStore ks = Encryptor.getToken();
		editor.putString(Encryptor.ENCRYPTION_BASE_KEY, ks.baseKey);
		editor.putString(Encryptor.ENCRYPTION_TOKEN, ks.token);
		editor.commit();
		
	}

	@SuppressLint("NewApi")
	public static void InitializeAndStartSession(Context context, String APIKEY) throws Exception {
		if (StateData.FirstConnect) {
			StateData.AppContext = context;
			StateData.FirstConnect = false;
			StateData.APIKEY = APIKEY;

			new UncaughtExceptionHandler();
			//처음 세션!
			sendSession(context, APIKEY);
		}
		
		//about init encrytion
		SharedPreferences prefs = context.getSharedPreferences(Encryptor.ENCRYPTION, Context.MODE_PRIVATE);
		String baseKey = prefs.getString(Encryptor.ENCRYPTION_BASE_KEY, null);
		String token = prefs.getString(Encryptor.ENCRYPTION_TOKEN, null);
		
		if(baseKey == null) {
			Encryptor.requestToken(context);
		} else  {
			Encryptor.token = token;
			Encryptor.baseKey = baseKey;
		}
		
		EventPathManager.ClearEvent();
	}

	private static void sendSession(Context context, String apiKey) {
		// Session 아이디 설정
		
		Authentication authentication = new Authentication();
		authentication.setKey(StateData.APIKEY);
		authentication.setAppVersion(DeviceCollector.GetAppVersion(context));
		authentication.setAndroidVersion(DeviceCollector.getVersionRelease());
		authentication.setModel(DeviceCollector.getDeviceModel());
		authentication.setManufacturer(DeviceCollector.getManufacturer());
		authentication.setCountryCode(DeviceCollector.getCountry(context));
		authentication.setDeviceId(DeviceCollector.getDeviceId(context, apiKey));
		authentication.setCarrierName(DeviceCollector.getCarrierName(context));
		Sender.sendSession(authentication, Sender.SESSION_URL);

	}


	public static void SendException(Exception e, String Tag, ErrorRank rank) {
		ErrorReport report = ErrorReportFactory.CreateErrorReport(e, Tag, rank,
				StateData.AppContext);
		
		try {
			Sender.sendException(report, Sender.EXCEPTION_URL);
		} catch (JSONException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}


	}

	public static void SendException(Exception e) {
		SendException(e, "", ErrorRank.Critical);
	}

	public static void SendException(Exception e, String Tag) {
		SendException(e, Tag, ErrorRank.Critical);
	}

	public static void SetLogCat(boolean toggleLog) {
		StateData.ToggleLogCat = toggleLog;
	}

	public static void SetLogging(int Line, String Filter) {
		StateData.TransferLog = true;
		StateData.LogLine = Line;
		StateData.LogFilter = Filter;
	}

	public static void SetLogging(int Line) {
		StateData.TransferLog = true;
		StateData.LogLine = Line;
	}

	public static int v(String tag, String Msg, Throwable tr) {
		return log(LogLevel.Verbose, tag, Msg, tr);
	}

	public static int v(String tag, String Msg) {
		return log(LogLevel.Verbose, tag, Msg, null);
	}

	public static int d(String tag, String Msg, Throwable tr) {
		return log(LogLevel.Debug, tag, Msg, tr);
	}

	public static int d(String tag, String Msg) {
		return log(LogLevel.Debug, tag, Msg, null);
	}

	public static int i(String tag, String Msg, Throwable tr) {
		return log(LogLevel.Info, tag, Msg, tr);
	}

	public static int i(String tag, String Msg) {
		return log(LogLevel.Info, tag, Msg, null);
	}

	public static int w(String tag, String Msg, Throwable tr) {
		return log(LogLevel.Warning, tag, Msg, tr);
	}

	public static int w(String tag, String Msg) {
		return log(LogLevel.Warning, tag, Msg, null);
	}

	public static int e(String tag, String Msg, Throwable tr) {
		return log(LogLevel.Error, tag, Msg, tr);
	}

	public static int e(String tag, String Msg) {
		return log(LogLevel.Error, tag, Msg, null);
	}

	enum LogLevel {
		Verbose, Debug, Info, Warning, Error
	}

	private static int loglevel(LogLevel level, String tag, String Msg,
			Throwable tr) {
		if (tr != null) {
			switch (level) {
			case Verbose:
				return Log.v(tag, Msg, tr);
			case Debug:
				return Log.d(tag, Msg, tr);
			case Info:
				return Log.i(tag, Msg, tr);
			case Warning:
				return Log.w(tag, Msg, tr);
			case Error:
				return Log.e(tag, Msg, tr);
			default:
				return 0;
			}
		} else {
			switch (level) {
			case Verbose:
				return Log.v(tag, Msg);
			case Debug:
				return Log.d(tag, Msg);
			case Info:
				return Log.i(tag, Msg);
			case Warning:
				return Log.w(tag, Msg);
			case Error:
				return Log.e(tag, Msg);
			default:
				return 0;
			}
		}

	}

	private static int log(LogLevel level, String tag, String Msg, Throwable tr) {
		EventPathManager.CreateEventPath(3, "");

		if (StateData.ToggleLogCat)
			return loglevel(level, tag, Msg, tr);
		else
			return 0;
	}

	private static String GetCachePath() {
		File cachefile = StateData.AppContext.getCacheDir();
		return cachefile.getAbsolutePath();
	}
	

}

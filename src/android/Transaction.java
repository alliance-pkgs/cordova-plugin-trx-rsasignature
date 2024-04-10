package com.cv.alliance.aop.trx;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

import android.annotation.TargetApi;

@TargetApi(23)
public class Transaction {

	/** The unique user ID who made the transaction */
	private final String mUserId;
	private final String mDate;

	public Transaction(String userId, String date) {
		mUserId = userId;
		mDate = date;
	}

	public String getMDate(){
        return mDate;
    }

	public String getUserId() {
		return mUserId;
	}

	public byte[] toByteArray() {
        String user = getUserId();
        String date = getMDate();
		user = user.concat(date);

		return user.getBytes();
	}
}
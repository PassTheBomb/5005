package enwei;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class MsgHandler {
	public static byte[] createNetworkMsg(byte[] encodedMsg){
		ByteBuffer byteBuffer = ByteBuffer.allocate(encodedMsg.length + 4);
		byteBuffer.putInt(encodedMsg.length);
		byteBuffer.put(encodedMsg);
		return byteBuffer.array();
	}

	public static byte[] acquireNetworkMsg(InputStream in) throws IOException{
		byte[] byteArray = new byte[4];
		in.read(byteArray,0,4);
		byteArray = new byte[ByteBuffer.wrap(byteArray).getInt()];
		in.read(byteArray);
		return byteArray;
	}
}

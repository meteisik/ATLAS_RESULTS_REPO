import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_ZephyrCipherSafe {

    public void openZephyrCipher() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_ZephyrCipherSafeSink()).readZephyrCipher(dataHashMap);
    }
}

class CWE22_P11_V1_ZephyrCipherSafeSink {
    public void readZephyrCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String zephyrCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrCipherFile = new File(zephyrCipherRoot + data);
            FileInputStream zephyrCipherStream = null;
            InputStreamReader zephyrCipherStreamReader = null;
            BufferedReader zephyrCipherReader = null;
            if (zephyrCipherFile.exists() && zephyrCipherFile.isFile()) {
                try {
                    zephyrCipherStream = new FileInputStream(zephyrCipherFile);
                    zephyrCipherStreamReader = new InputStreamReader(zephyrCipherStream, "UTF-8");
                    zephyrCipherReader = new BufferedReader(zephyrCipherStreamReader);
                    System.out.println(zephyrCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_ZephyrCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrCipherReader != null) {
                            zephyrCipherReader.close();
                        }
                        if (zephyrCipherStreamReader != null) {
                            zephyrCipherStreamReader.close();
                        }
                        if (zephyrCipherStream != null) {
                            zephyrCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_ZephyrCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

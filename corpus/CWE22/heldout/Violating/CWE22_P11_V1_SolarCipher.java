import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SolarCipher {

    public void openSolarCipher() {
        String data;
        data = System.getenv("SOLAR_CIPHER_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SolarCipherSink()).readSolarCipher(dataHashMap);
    }
}

class CWE22_P11_V1_SolarCipherSink {
    public void readSolarCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String solarCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File solarCipherFile = new File(solarCipherRoot + data);
            FileInputStream solarCipherStream = null;
            InputStreamReader solarCipherStreamReader = null;
            BufferedReader solarCipherReader = null;
            if (solarCipherFile.exists() && solarCipherFile.isFile()) {
                try {
                    solarCipherStream = new FileInputStream(solarCipherFile);
                    solarCipherStreamReader = new InputStreamReader(solarCipherStream, "UTF-8");
                    solarCipherReader = new BufferedReader(solarCipherStreamReader);
                    System.out.println(solarCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SolarCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (solarCipherReader != null) {
                            solarCipherReader.close();
                        }
                        if (solarCipherStreamReader != null) {
                            solarCipherStreamReader.close();
                        }
                        if (solarCipherStream != null) {
                            solarCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SolarCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

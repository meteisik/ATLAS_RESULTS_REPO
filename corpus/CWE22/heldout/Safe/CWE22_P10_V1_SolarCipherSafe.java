import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SolarCipherSafe {
    public static String data;

    public void openSolarCipher() {
        data = "foo";
        (new CWE22_P10_V1_SolarCipherSafeSink()).readSolarCipher();
    }
}

class CWE22_P10_V1_SolarCipherSafeSink {
    public void readSolarCipher() {
        String data = CWE22_P10_V1_SolarCipherSafe.data;
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
                    Logger.getLogger("CWE22_P10_V1_SolarCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V1_SolarCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

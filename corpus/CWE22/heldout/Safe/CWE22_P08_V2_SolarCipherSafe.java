import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SolarCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSolarCipher() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SolarCipherSafeSink()).readSolarCipher(dataArray);
    }
}

class CWE22_P08_V2_SolarCipherSafeSink {
    public void readSolarCipher(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SolarCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SolarCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

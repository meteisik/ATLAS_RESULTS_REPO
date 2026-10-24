import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SilentKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openSilentKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE22_P07_V2_SilentKestrelSafeSource()).locateSilentKestrel();
        } else {
            data = null;
        }
        String silentKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File silentKestrelFile = new File(silentKestrelRoot + data);
            FileInputStream silentKestrelStream = null;
            InputStreamReader silentKestrelStreamReader = null;
            BufferedReader silentKestrelReader = null;
            if (silentKestrelFile.exists() && silentKestrelFile.isFile()) {
                try {
                    silentKestrelStream = new FileInputStream(silentKestrelFile);
                    silentKestrelStreamReader = new InputStreamReader(silentKestrelStream, "UTF-8");
                    silentKestrelReader = new BufferedReader(silentKestrelStreamReader);
                    System.out.println(silentKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SilentKestrelSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentKestrelReader != null) {
                            silentKestrelReader.close();
                        }
                        if (silentKestrelStreamReader != null) {
                            silentKestrelStreamReader.close();
                        }
                        if (silentKestrelStream != null) {
                            silentKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SilentKestrelSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SilentKestrelSafeSource {
    public String locateSilentKestrel() {
        String data;
        data = "foo";
        return data;
    }
}

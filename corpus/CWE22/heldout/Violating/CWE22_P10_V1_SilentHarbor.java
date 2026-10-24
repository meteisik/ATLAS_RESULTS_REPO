import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SilentHarbor {
    public static String data;

    public void openSilentHarbor() {
        data = System.getenv("SILENT_HARBOR_PATH");
        (new CWE22_P10_V1_SilentHarborSink()).readSilentHarbor();
    }
}

class CWE22_P10_V1_SilentHarborSink {
    public void readSilentHarbor() {
        String data = CWE22_P10_V1_SilentHarbor.data;
        String silentHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File silentHarborFile = new File(silentHarborRoot + data);
            FileInputStream silentHarborStream = null;
            InputStreamReader silentHarborStreamReader = null;
            BufferedReader silentHarborReader = null;
            if (silentHarborFile.exists() && silentHarborFile.isFile()) {
                try {
                    silentHarborStream = new FileInputStream(silentHarborFile);
                    silentHarborStreamReader = new InputStreamReader(silentHarborStream, "UTF-8");
                    silentHarborReader = new BufferedReader(silentHarborStreamReader);
                    System.out.println(silentHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_SilentHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentHarborReader != null) {
                            silentHarborReader.close();
                        }
                        if (silentHarborStreamReader != null) {
                            silentHarborStreamReader.close();
                        }
                        if (silentHarborStream != null) {
                            silentHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_SilentHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_VividAuroraSafe {
    public static String data;

    public void openVividAurora() {
        data = "foo";
        (new CWE22_P10_V1_VividAuroraSafeSink()).readVividAurora();
    }
}

class CWE22_P10_V1_VividAuroraSafeSink {
    public void readVividAurora() {
        String data = CWE22_P10_V1_VividAuroraSafe.data;
        String vividAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File vividAuroraFile = new File(vividAuroraRoot + data);
            FileInputStream vividAuroraStream = null;
            InputStreamReader vividAuroraStreamReader = null;
            BufferedReader vividAuroraReader = null;
            if (vividAuroraFile.exists() && vividAuroraFile.isFile()) {
                try {
                    vividAuroraStream = new FileInputStream(vividAuroraFile);
                    vividAuroraStreamReader = new InputStreamReader(vividAuroraStream, "UTF-8");
                    vividAuroraReader = new BufferedReader(vividAuroraStreamReader);
                    System.out.println(vividAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_VividAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividAuroraReader != null) {
                            vividAuroraReader.close();
                        }
                        if (vividAuroraStreamReader != null) {
                            vividAuroraStreamReader.close();
                        }
                        if (vividAuroraStream != null) {
                            vividAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_VividAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

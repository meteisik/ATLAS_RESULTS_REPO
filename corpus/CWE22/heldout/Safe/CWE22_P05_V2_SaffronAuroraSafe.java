import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_SaffronAuroraSafe {
    private String saffronAuroraData;
    private static boolean privateTrue = true;

    private void readSaffronAurora() {
        String data = saffronAuroraData;
        String saffronAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronAuroraFile = new File(saffronAuroraRoot + data);
            FileInputStream saffronAuroraStream = null;
            InputStreamReader saffronAuroraStreamReader = null;
            BufferedReader saffronAuroraReader = null;
            if (saffronAuroraFile.exists() && saffronAuroraFile.isFile()) {
                try {
                    saffronAuroraStream = new FileInputStream(saffronAuroraFile);
                    saffronAuroraStreamReader = new InputStreamReader(saffronAuroraStream, "UTF-8");
                    saffronAuroraReader = new BufferedReader(saffronAuroraStreamReader);
                    System.out.println(saffronAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_SaffronAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronAuroraReader != null) {
                            saffronAuroraReader.close();
                        }
                        if (saffronAuroraStreamReader != null) {
                            saffronAuroraStreamReader.close();
                        }
                        if (saffronAuroraStream != null) {
                            saffronAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_SaffronAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openSaffronAurora() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        saffronAuroraData = data;
        readSaffronAurora();
    }
}

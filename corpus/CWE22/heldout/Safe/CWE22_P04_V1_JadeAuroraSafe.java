import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_JadeAuroraSafe {

    private String locateJadeAurora() {
        String data;
        data = "foo";
        return data;
    }

    public void openJadeAurora() {
        String data = locateJadeAurora();
        String jadeAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeAuroraFile = new File(jadeAuroraRoot + data);
            FileInputStream jadeAuroraStream = null;
            InputStreamReader jadeAuroraStreamReader = null;
            BufferedReader jadeAuroraReader = null;
            if (jadeAuroraFile.exists() && jadeAuroraFile.isFile()) {
                try {
                    jadeAuroraStream = new FileInputStream(jadeAuroraFile);
                    jadeAuroraStreamReader = new InputStreamReader(jadeAuroraStream, "UTF-8");
                    jadeAuroraReader = new BufferedReader(jadeAuroraStreamReader);
                    System.out.println(jadeAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_JadeAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeAuroraReader != null) {
                            jadeAuroraReader.close();
                        }
                        if (jadeAuroraStreamReader != null) {
                            jadeAuroraStreamReader.close();
                        }
                        if (jadeAuroraStream != null) {
                            jadeAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_JadeAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

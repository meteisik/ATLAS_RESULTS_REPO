import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_NovaAuroraSafe {

    public void openNovaAurora() {
        String data;
        data = "foo";
        (new CWE22_P06_V1_NovaAuroraSafeSink()).readNovaAurora(data);
    }
}

class CWE22_P06_V1_NovaAuroraSafeSink {
    public void readNovaAurora(String data) {
        String novaAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File novaAuroraFile = new File(novaAuroraRoot + data);
            FileInputStream novaAuroraStream = null;
            InputStreamReader novaAuroraStreamReader = null;
            BufferedReader novaAuroraReader = null;
            if (novaAuroraFile.exists() && novaAuroraFile.isFile()) {
                try {
                    novaAuroraStream = new FileInputStream(novaAuroraFile);
                    novaAuroraStreamReader = new InputStreamReader(novaAuroraStream, "UTF-8");
                    novaAuroraReader = new BufferedReader(novaAuroraStreamReader);
                    System.out.println(novaAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_NovaAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaAuroraReader != null) {
                            novaAuroraReader.close();
                        }
                        if (novaAuroraStreamReader != null) {
                            novaAuroraStreamReader.close();
                        }
                        if (novaAuroraStream != null) {
                            novaAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_NovaAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ZephyrAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void openZephyrAurora() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ZephyrAuroraSafeSink()).readZephyrAurora(dataContainer);
    }
}

class CWE22_P09_V2_ZephyrAuroraSafeSink {
    public void readZephyrAurora(CWE22_P09_V2_ZephyrAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String zephyrAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrAuroraFile = new File(zephyrAuroraRoot + data);
            FileInputStream zephyrAuroraStream = null;
            InputStreamReader zephyrAuroraStreamReader = null;
            BufferedReader zephyrAuroraReader = null;
            if (zephyrAuroraFile.exists() && zephyrAuroraFile.isFile()) {
                try {
                    zephyrAuroraStream = new FileInputStream(zephyrAuroraFile);
                    zephyrAuroraStreamReader = new InputStreamReader(zephyrAuroraStream, "UTF-8");
                    zephyrAuroraReader = new BufferedReader(zephyrAuroraStreamReader);
                    System.out.println(zephyrAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ZephyrAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrAuroraReader != null) {
                            zephyrAuroraReader.close();
                        }
                        if (zephyrAuroraStreamReader != null) {
                            zephyrAuroraStreamReader.close();
                        }
                        if (zephyrAuroraStream != null) {
                            zephyrAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ZephyrAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VividAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void openVividAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VividAuroraSafeSink()).readVividAurora(dataContainer);
    }
}

class CWE22_P09_V2_VividAuroraSafeSink {
    public void readVividAurora(CWE22_P09_V2_VividAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V2_VividAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V2_VividAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

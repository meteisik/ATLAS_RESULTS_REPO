import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberAuroraSafe {
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

    public void openAmberAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberAuroraSafeSink()).readAmberAurora(dataContainer);
    }
}

class CWE22_P09_V2_AmberAuroraSafeSink {
    public void readAmberAurora(CWE22_P09_V2_AmberAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File amberAuroraFile = new File(amberAuroraRoot + data);
            FileInputStream amberAuroraStream = null;
            InputStreamReader amberAuroraStreamReader = null;
            BufferedReader amberAuroraReader = null;
            if (amberAuroraFile.exists() && amberAuroraFile.isFile()) {
                try {
                    amberAuroraStream = new FileInputStream(amberAuroraFile);
                    amberAuroraStreamReader = new InputStreamReader(amberAuroraStream, "UTF-8");
                    amberAuroraReader = new BufferedReader(amberAuroraStreamReader);
                    System.out.println(amberAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberAuroraReader != null) {
                            amberAuroraReader.close();
                        }
                        if (amberAuroraStreamReader != null) {
                            amberAuroraStreamReader.close();
                        }
                        if (amberAuroraStream != null) {
                            amberAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

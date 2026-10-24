import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ZephyrSundialSafe {
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

    public void openZephyrSundial() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ZephyrSundialSafeSink()).readZephyrSundial(dataContainer);
    }
}

class CWE22_P09_V2_ZephyrSundialSafeSink {
    public void readZephyrSundial(CWE22_P09_V2_ZephyrSundialSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String zephyrSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrSundialFile = new File(zephyrSundialRoot + data);
            FileInputStream zephyrSundialStream = null;
            InputStreamReader zephyrSundialStreamReader = null;
            BufferedReader zephyrSundialReader = null;
            if (zephyrSundialFile.exists() && zephyrSundialFile.isFile()) {
                try {
                    zephyrSundialStream = new FileInputStream(zephyrSundialFile);
                    zephyrSundialStreamReader = new InputStreamReader(zephyrSundialStream, "UTF-8");
                    zephyrSundialReader = new BufferedReader(zephyrSundialStreamReader);
                    System.out.println(zephyrSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ZephyrSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrSundialReader != null) {
                            zephyrSundialReader.close();
                        }
                        if (zephyrSundialStreamReader != null) {
                            zephyrSundialStreamReader.close();
                        }
                        if (zephyrSundialStream != null) {
                            zephyrSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ZephyrSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

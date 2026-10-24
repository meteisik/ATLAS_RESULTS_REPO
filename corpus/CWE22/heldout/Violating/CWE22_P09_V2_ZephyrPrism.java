import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ZephyrPrism {
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

    public void openZephyrPrism() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_PRISM_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ZephyrPrismSink()).readZephyrPrism(dataContainer);
    }
}

class CWE22_P09_V2_ZephyrPrismSink {
    public void readZephyrPrism(CWE22_P09_V2_ZephyrPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
        String zephyrPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrPrismFile = new File(zephyrPrismRoot + data);
            FileInputStream zephyrPrismStream = null;
            InputStreamReader zephyrPrismStreamReader = null;
            BufferedReader zephyrPrismReader = null;
            if (zephyrPrismFile.exists() && zephyrPrismFile.isFile()) {
                try {
                    zephyrPrismStream = new FileInputStream(zephyrPrismFile);
                    zephyrPrismStreamReader = new InputStreamReader(zephyrPrismStream, "UTF-8");
                    zephyrPrismReader = new BufferedReader(zephyrPrismStreamReader);
                    System.out.println(zephyrPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ZephyrPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrPrismReader != null) {
                            zephyrPrismReader.close();
                        }
                        if (zephyrPrismStreamReader != null) {
                            zephyrPrismStreamReader.close();
                        }
                        if (zephyrPrismStream != null) {
                            zephyrPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ZephyrPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_ZephyrPrism {
    private static int privateFive = 5;

    public void openZephyrPrism() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_PRISM_PATH");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_ZephyrPrismSink()).readZephyrPrism(dataArray);
    }
}

class CWE22_P08_V2_ZephyrPrismSink {
    public void readZephyrPrism(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_ZephyrPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_ZephyrPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

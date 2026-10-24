import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ZephyrCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void openZephyrCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_CIPHER_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ZephyrCipherSink()).readZephyrCipher(dataContainer);
    }
}

class CWE22_P09_V2_ZephyrCipherSink {
    public void readZephyrCipher(CWE22_P09_V2_ZephyrCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        String zephyrCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrCipherFile = new File(zephyrCipherRoot + data);
            FileInputStream zephyrCipherStream = null;
            InputStreamReader zephyrCipherStreamReader = null;
            BufferedReader zephyrCipherReader = null;
            if (zephyrCipherFile.exists() && zephyrCipherFile.isFile()) {
                try {
                    zephyrCipherStream = new FileInputStream(zephyrCipherFile);
                    zephyrCipherStreamReader = new InputStreamReader(zephyrCipherStream, "UTF-8");
                    zephyrCipherReader = new BufferedReader(zephyrCipherStreamReader);
                    System.out.println(zephyrCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ZephyrCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrCipherReader != null) {
                            zephyrCipherReader.close();
                        }
                        if (zephyrCipherStreamReader != null) {
                            zephyrCipherStreamReader.close();
                        }
                        if (zephyrCipherStream != null) {
                            zephyrCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ZephyrCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

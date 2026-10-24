import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureCipher() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureCipherSafeBase baseObject = new CWE22_P12_V2_AzureCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureCipherSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureCipherSafeSink extends CWE22_P12_V2_AzureCipherSafeBase {
    public void action(String data) {
        String azureCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File azureCipherFile = new File(azureCipherRoot + data);
            FileInputStream azureCipherStream = null;
            InputStreamReader azureCipherStreamReader = null;
            BufferedReader azureCipherReader = null;
            if (azureCipherFile.exists() && azureCipherFile.isFile()) {
                try {
                    azureCipherStream = new FileInputStream(azureCipherFile);
                    azureCipherStreamReader = new InputStreamReader(azureCipherStream, "UTF-8");
                    azureCipherReader = new BufferedReader(azureCipherStreamReader);
                    System.out.println(azureCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_AzureCipherSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureCipherReader != null) {
                            azureCipherReader.close();
                        }
                        if (azureCipherStreamReader != null) {
                            azureCipherStreamReader.close();
                        }
                        if (azureCipherStream != null) {
                            azureCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_AzureCipherSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureCascade() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureCascadeSafeBase baseObject = new CWE22_P12_V2_AzureCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureCascadeSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureCascadeSafeSink extends CWE22_P12_V2_AzureCascadeSafeBase {
    public void action(String data) {
        String azureCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File azureCascadeFile = new File(azureCascadeRoot + data);
            FileInputStream azureCascadeStream = null;
            InputStreamReader azureCascadeStreamReader = null;
            BufferedReader azureCascadeReader = null;
            if (azureCascadeFile.exists() && azureCascadeFile.isFile()) {
                try {
                    azureCascadeStream = new FileInputStream(azureCascadeFile);
                    azureCascadeStreamReader = new InputStreamReader(azureCascadeStream, "UTF-8");
                    azureCascadeReader = new BufferedReader(azureCascadeStreamReader);
                    System.out.println(azureCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureCascadeReader != null) {
                            azureCascadeReader.close();
                        }
                        if (azureCascadeStreamReader != null) {
                            azureCascadeStreamReader.close();
                        }
                        if (azureCascadeStream != null) {
                            azureCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

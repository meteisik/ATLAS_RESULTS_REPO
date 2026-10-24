import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureFlare() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureFlareSafeBase baseObject = new CWE22_P12_V2_AzureFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureFlareSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureFlareSafeSink extends CWE22_P12_V2_AzureFlareSafeBase {
    public void action(String data) {
        String azureFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File azureFlareFile = new File(azureFlareRoot + data);
            FileInputStream azureFlareStream = null;
            InputStreamReader azureFlareStreamReader = null;
            BufferedReader azureFlareReader = null;
            if (azureFlareFile.exists() && azureFlareFile.isFile()) {
                try {
                    azureFlareStream = new FileInputStream(azureFlareFile);
                    azureFlareStreamReader = new InputStreamReader(azureFlareStream, "UTF-8");
                    azureFlareReader = new BufferedReader(azureFlareStreamReader);
                    System.out.println(azureFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_AzureFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureFlareReader != null) {
                            azureFlareReader.close();
                        }
                        if (azureFlareStreamReader != null) {
                            azureFlareStreamReader.close();
                        }
                        if (azureFlareStream != null) {
                            azureFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_AzureFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

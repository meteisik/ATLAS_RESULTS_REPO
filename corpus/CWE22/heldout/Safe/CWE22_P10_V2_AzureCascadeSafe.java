import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_AzureCascadeSafe {
    public static String data;
    private static boolean privateTrue = true;

    public void openAzureCascade() {
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_AzureCascadeSafeSink()).readAzureCascade();
    }
}

class CWE22_P10_V2_AzureCascadeSafeSink {
    public void readAzureCascade() {
        String data = CWE22_P10_V2_AzureCascadeSafe.data;
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
                    Logger.getLogger("CWE22_P10_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

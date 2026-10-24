import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void openAzureAurora() {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureAuroraSafeBase baseObject = new CWE22_P12_V2_AzureAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureAuroraSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureAuroraSafeSink extends CWE22_P12_V2_AzureAuroraSafeBase {
    public void action(String data) {
        String azureAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File azureAuroraFile = new File(azureAuroraRoot + data);
            FileInputStream azureAuroraStream = null;
            InputStreamReader azureAuroraStreamReader = null;
            BufferedReader azureAuroraReader = null;
            if (azureAuroraFile.exists() && azureAuroraFile.isFile()) {
                try {
                    azureAuroraStream = new FileInputStream(azureAuroraFile);
                    azureAuroraStreamReader = new InputStreamReader(azureAuroraStream, "UTF-8");
                    azureAuroraReader = new BufferedReader(azureAuroraStreamReader);
                    System.out.println(azureAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_AzureAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureAuroraReader != null) {
                            azureAuroraReader.close();
                        }
                        if (azureAuroraStreamReader != null) {
                            azureAuroraStreamReader.close();
                        }
                        if (azureAuroraStream != null) {
                            azureAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_AzureAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

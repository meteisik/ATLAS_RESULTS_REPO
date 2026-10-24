import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureAurora {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openAzureAurora() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_AURORA_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureAuroraSink()).readAzureAurora(dataHashMap);
    }
}

class CWE22_P11_V2_AzureAuroraSink {
    public void readAzureAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V2_AzureAuroraSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V2_AzureAuroraSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

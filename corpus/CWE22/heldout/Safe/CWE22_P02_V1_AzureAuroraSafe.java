import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureAuroraSafe {

    public void openAzureAurora() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_AzureAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_AzureAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

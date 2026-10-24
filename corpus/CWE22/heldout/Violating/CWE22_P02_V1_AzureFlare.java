import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureFlare {

    public void openAzureFlare() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_FLARE_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_AzureFlare").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_AzureFlare").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

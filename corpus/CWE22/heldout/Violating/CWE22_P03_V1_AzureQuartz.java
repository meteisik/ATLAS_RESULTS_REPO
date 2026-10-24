import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_AzureQuartz {

    private void readAzureQuartz(String data) {
        String azureQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File azureQuartzFile = new File(azureQuartzRoot + data);
            FileInputStream azureQuartzStream = null;
            InputStreamReader azureQuartzStreamReader = null;
            BufferedReader azureQuartzReader = null;
            if (azureQuartzFile.exists() && azureQuartzFile.isFile()) {
                try {
                    azureQuartzStream = new FileInputStream(azureQuartzFile);
                    azureQuartzStreamReader = new InputStreamReader(azureQuartzStream, "UTF-8");
                    azureQuartzReader = new BufferedReader(azureQuartzStreamReader);
                    System.out.println(azureQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_AzureQuartz").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureQuartzReader != null) {
                            azureQuartzReader.close();
                        }
                        if (azureQuartzStreamReader != null) {
                            azureQuartzStreamReader.close();
                        }
                        if (azureQuartzStream != null) {
                            azureQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_AzureQuartz").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openAzureQuartz() {
        String data;
        data = System.getenv("AZURE_QUARTZ_PATH");
        readAzureQuartz(data);
    }
}

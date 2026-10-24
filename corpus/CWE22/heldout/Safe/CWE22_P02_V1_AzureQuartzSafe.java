import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureQuartzSafe {

    public void openAzureQuartz() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_AzureQuartzSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_AzureQuartzSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

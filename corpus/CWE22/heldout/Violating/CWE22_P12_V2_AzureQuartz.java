import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureQuartz {

    public void openAzureQuartz() {
        String data;
        while (true) {
            data = System.getenv("AZURE_QUARTZ_PATH");
            break;
        }
        CWE22_P12_V2_AzureQuartzBase baseObject = new CWE22_P12_V2_AzureQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureQuartzBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureQuartzSink extends CWE22_P12_V2_AzureQuartzBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_AzureQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_AzureQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

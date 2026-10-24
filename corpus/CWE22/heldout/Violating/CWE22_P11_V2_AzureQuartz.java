import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureQuartz() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AZURE_QUARTZ_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureQuartzSink()).readAzureQuartz(dataHashMap);
    }
}

class CWE22_P11_V2_AzureQuartzSink {
    public void readAzureQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V2_AzureQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V2_AzureQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

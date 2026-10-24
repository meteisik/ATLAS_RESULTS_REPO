import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureGlint() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AZURE_GLINT_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureGlintSink()).readAzureGlint(dataHashMap);
    }
}

class CWE22_P11_V2_AzureGlintSink {
    public void readAzureGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String azureGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File azureGlintFile = new File(azureGlintRoot + data);
            FileInputStream azureGlintStream = null;
            InputStreamReader azureGlintStreamReader = null;
            BufferedReader azureGlintReader = null;
            if (azureGlintFile.exists() && azureGlintFile.isFile()) {
                try {
                    azureGlintStream = new FileInputStream(azureGlintFile);
                    azureGlintStreamReader = new InputStreamReader(azureGlintStream, "UTF-8");
                    azureGlintReader = new BufferedReader(azureGlintStreamReader);
                    System.out.println(azureGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AzureGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureGlintReader != null) {
                            azureGlintReader.close();
                        }
                        if (azureGlintStreamReader != null) {
                            azureGlintStreamReader.close();
                        }
                        if (azureGlintStream != null) {
                            azureGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AzureGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

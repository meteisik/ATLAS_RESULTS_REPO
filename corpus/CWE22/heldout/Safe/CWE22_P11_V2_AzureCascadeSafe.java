import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureCascadeSafe {
    private static int privateFive = 5;

    public void openAzureCascade() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureCascadeSafeSink()).readAzureCascade(dataHashMap);
    }
}

class CWE22_P11_V2_AzureCascadeSafeSink {
    public void readAzureCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V2_AzureCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureSundialSafe {

    public void openAzureSundial() {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureSundialSafeSink()).readAzureSundial(dataHashMap);
    }
}

class CWE22_P11_V2_AzureSundialSafeSink {
    public void readAzureSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String azureSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File azureSundialFile = new File(azureSundialRoot + data);
            FileInputStream azureSundialStream = null;
            InputStreamReader azureSundialStreamReader = null;
            BufferedReader azureSundialReader = null;
            if (azureSundialFile.exists() && azureSundialFile.isFile()) {
                try {
                    azureSundialStream = new FileInputStream(azureSundialFile);
                    azureSundialStreamReader = new InputStreamReader(azureSundialStream, "UTF-8");
                    azureSundialReader = new BufferedReader(azureSundialStreamReader);
                    System.out.println(azureSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AzureSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureSundialReader != null) {
                            azureSundialReader.close();
                        }
                        if (azureSundialStreamReader != null) {
                            azureSundialStreamReader.close();
                        }
                        if (azureSundialStream != null) {
                            azureSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AzureSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureSignal {

    public void openAzureSignal() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_SIGNAL_PATH");
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureSignalSink()).readAzureSignal(dataHashMap);
    }
}

class CWE22_P11_V2_AzureSignalSink {
    public void readAzureSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String azureSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File azureSignalFile = new File(azureSignalRoot + data);
            FileInputStream azureSignalStream = null;
            InputStreamReader azureSignalStreamReader = null;
            BufferedReader azureSignalReader = null;
            if (azureSignalFile.exists() && azureSignalFile.isFile()) {
                try {
                    azureSignalStream = new FileInputStream(azureSignalFile);
                    azureSignalStreamReader = new InputStreamReader(azureSignalStream, "UTF-8");
                    azureSignalReader = new BufferedReader(azureSignalStreamReader);
                    System.out.println(azureSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AzureSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureSignalReader != null) {
                            azureSignalReader.close();
                        }
                        if (azureSignalStreamReader != null) {
                            azureSignalStreamReader.close();
                        }
                        if (azureSignalStream != null) {
                            azureSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AzureSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

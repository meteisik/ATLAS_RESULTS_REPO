import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzureCipher {
    private static boolean privateReturnsTrue() { return true; }

    public void openAzureCipher() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_CIPHER_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzureCipherSink()).readAzureCipher(dataHashMap);
    }
}

class CWE22_P11_V2_AzureCipherSink {
    public void readAzureCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String azureCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File azureCipherFile = new File(azureCipherRoot + data);
            FileInputStream azureCipherStream = null;
            InputStreamReader azureCipherStreamReader = null;
            BufferedReader azureCipherReader = null;
            if (azureCipherFile.exists() && azureCipherFile.isFile()) {
                try {
                    azureCipherStream = new FileInputStream(azureCipherFile);
                    azureCipherStreamReader = new InputStreamReader(azureCipherStream, "UTF-8");
                    azureCipherReader = new BufferedReader(azureCipherStreamReader);
                    System.out.println(azureCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AzureCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureCipherReader != null) {
                            azureCipherReader.close();
                        }
                        if (azureCipherStreamReader != null) {
                            azureCipherStreamReader.close();
                        }
                        if (azureCipherStream != null) {
                            azureCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AzureCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

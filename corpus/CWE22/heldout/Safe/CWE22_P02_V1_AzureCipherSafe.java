import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureCipherSafe {

    public void openAzureCipher() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_AzureCipherSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_AzureCipherSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

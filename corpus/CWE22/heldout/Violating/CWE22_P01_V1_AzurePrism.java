import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_AzurePrism {

    public void openAzurePrism() {
        String data;
        data = System.getenv("AZURE_PRISM_PATH");
        String azurePrismRoot = "/home/user/uploads/";
        if (data != null) {
            File azurePrismFile = new File(azurePrismRoot + data);
            FileInputStream azurePrismStream = null;
            InputStreamReader azurePrismStreamReader = null;
            BufferedReader azurePrismReader = null;
            if (azurePrismFile.exists() && azurePrismFile.isFile()) {
                try {
                    azurePrismStream = new FileInputStream(azurePrismFile);
                    azurePrismStreamReader = new InputStreamReader(azurePrismStream, "UTF-8");
                    azurePrismReader = new BufferedReader(azurePrismStreamReader);
                    System.out.println(azurePrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_AzurePrism").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azurePrismReader != null) {
                            azurePrismReader.close();
                        }
                        if (azurePrismStreamReader != null) {
                            azurePrismStreamReader.close();
                        }
                        if (azurePrismStream != null) {
                            azurePrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_AzurePrism").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

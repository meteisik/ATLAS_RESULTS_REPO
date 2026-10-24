import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzurePrism {

    public void openAzurePrism() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_PRISM_PATH");
            break;
        default:
            data = null;
            break;
        }
        CWE22_P12_V2_AzurePrismBase baseObject = new CWE22_P12_V2_AzurePrismSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzurePrismBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzurePrismSink extends CWE22_P12_V2_AzurePrismBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_AzurePrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_AzurePrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureSundial {

    public void openAzureSundial() {
        String data;
        if (true) {
            data = System.getenv("AZURE_SUNDIAL_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureSundialBase baseObject = new CWE22_P12_V2_AzureSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureSundialBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureSundialSink extends CWE22_P12_V2_AzureSundialBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_AzureSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_AzureSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

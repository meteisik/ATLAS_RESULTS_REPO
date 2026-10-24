import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_AzureMantis {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzureMantis() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AZURE_MANTIS_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_AzureMantisBase baseObject = new CWE22_P12_V2_AzureMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_AzureMantisBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_AzureMantisSink extends CWE22_P12_V2_AzureMantisBase {
    public void action(String data) {
        String azureMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File azureMantisFile = new File(azureMantisRoot + data);
            FileInputStream azureMantisStream = null;
            InputStreamReader azureMantisStreamReader = null;
            BufferedReader azureMantisReader = null;
            if (azureMantisFile.exists() && azureMantisFile.isFile()) {
                try {
                    azureMantisStream = new FileInputStream(azureMantisFile);
                    azureMantisStreamReader = new InputStreamReader(azureMantisStream, "UTF-8");
                    azureMantisReader = new BufferedReader(azureMantisStreamReader);
                    System.out.println(azureMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_AzureMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azureMantisReader != null) {
                            azureMantisReader.close();
                        }
                        if (azureMantisStreamReader != null) {
                            azureMantisStreamReader.close();
                        }
                        if (azureMantisStream != null) {
                            azureMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_AzureMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

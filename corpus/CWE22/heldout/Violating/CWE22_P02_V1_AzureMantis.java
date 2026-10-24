import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureMantis {

    public void openAzureMantis() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_MANTIS_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_AzureMantis").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_AzureMantis").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

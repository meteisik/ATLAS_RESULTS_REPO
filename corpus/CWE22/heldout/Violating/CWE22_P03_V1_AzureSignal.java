import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_AzureSignal {

    private void readAzureSignal(String data) {
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
                    Logger.getLogger("CWE22_P03_V1_AzureSignal").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P03_V1_AzureSignal").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openAzureSignal() {
        String data;
        data = System.getenv("AZURE_SIGNAL_PATH");
        readAzureSignal(data);
    }
}

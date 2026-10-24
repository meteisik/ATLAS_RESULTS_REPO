import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureCascadeSafe {

    public void openAzureCascade() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String azureCascadeRoot = "/home/user/uploads/";
            if (data != null) {
                File azureCascadeFile = new File(azureCascadeRoot + data);
                FileInputStream azureCascadeStream = null;
                InputStreamReader azureCascadeStreamReader = null;
                BufferedReader azureCascadeReader = null;
                if (azureCascadeFile.exists() && azureCascadeFile.isFile()) {
                    try {
                        azureCascadeStream = new FileInputStream(azureCascadeFile);
                        azureCascadeStreamReader = new InputStreamReader(azureCascadeStream, "UTF-8");
                        azureCascadeReader = new BufferedReader(azureCascadeStreamReader);
                        System.out.println(azureCascadeReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_AzureCascadeSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (azureCascadeReader != null) {
                                azureCascadeReader.close();
                            }
                            if (azureCascadeStreamReader != null) {
                                azureCascadeStreamReader.close();
                            }
                            if (azureCascadeStream != null) {
                                azureCascadeStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_AzureCascadeSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

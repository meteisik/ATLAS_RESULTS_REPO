import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_AzureGlint {

    public void openAzureGlint() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_GLINT_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String azureGlintRoot = "/home/user/uploads/";
            if (data != null) {
                File azureGlintFile = new File(azureGlintRoot + data);
                FileInputStream azureGlintStream = null;
                InputStreamReader azureGlintStreamReader = null;
                BufferedReader azureGlintReader = null;
                if (azureGlintFile.exists() && azureGlintFile.isFile()) {
                    try {
                        azureGlintStream = new FileInputStream(azureGlintFile);
                        azureGlintStreamReader = new InputStreamReader(azureGlintStream, "UTF-8");
                        azureGlintReader = new BufferedReader(azureGlintStreamReader);
                        System.out.println(azureGlintReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_AzureGlint").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (azureGlintReader != null) {
                                azureGlintReader.close();
                            }
                            if (azureGlintStreamReader != null) {
                                azureGlintStreamReader.close();
                            }
                            if (azureGlintStream != null) {
                                azureGlintStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_AzureGlint").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_NovaAurora {
    private static boolean privateReturnsTrue() { return true; }

    public void openNovaAurora() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("NOVA_AURORA_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String novaAuroraRoot = "/home/user/uploads/";
            if (data != null) {
                File novaAuroraFile = new File(novaAuroraRoot + data);
                FileInputStream novaAuroraStream = null;
                InputStreamReader novaAuroraStreamReader = null;
                BufferedReader novaAuroraReader = null;
                if (novaAuroraFile.exists() && novaAuroraFile.isFile()) {
                    try {
                        novaAuroraStream = new FileInputStream(novaAuroraFile);
                        novaAuroraStreamReader = new InputStreamReader(novaAuroraStream, "UTF-8");
                        novaAuroraReader = new BufferedReader(novaAuroraStreamReader);
                        System.out.println(novaAuroraReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_NovaAurora").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (novaAuroraReader != null) {
                                novaAuroraReader.close();
                            }
                            if (novaAuroraStreamReader != null) {
                                novaAuroraStreamReader.close();
                            }
                            if (novaAuroraStream != null) {
                                novaAuroraStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_NovaAurora").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

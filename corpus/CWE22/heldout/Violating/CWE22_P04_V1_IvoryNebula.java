import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_IvoryNebula {

    private String locateIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_PATH");
        return data;
    }

    public void openIvoryNebula() {
        String data = locateIvoryNebula();
        String ivoryNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryNebulaFile = new File(ivoryNebulaRoot + data);
            FileInputStream ivoryNebulaStream = null;
            InputStreamReader ivoryNebulaStreamReader = null;
            BufferedReader ivoryNebulaReader = null;
            if (ivoryNebulaFile.exists() && ivoryNebulaFile.isFile()) {
                try {
                    ivoryNebulaStream = new FileInputStream(ivoryNebulaFile);
                    ivoryNebulaStreamReader = new InputStreamReader(ivoryNebulaStream, "UTF-8");
                    ivoryNebulaReader = new BufferedReader(ivoryNebulaStreamReader);
                    System.out.println(ivoryNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_IvoryNebula").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryNebulaReader != null) {
                            ivoryNebulaReader.close();
                        }
                        if (ivoryNebulaStreamReader != null) {
                            ivoryNebulaStreamReader.close();
                        }
                        if (ivoryNebulaStream != null) {
                            ivoryNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_IvoryNebula").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

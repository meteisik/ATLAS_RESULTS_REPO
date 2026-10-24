import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_IvoryLanternSafe {
    private String ivoryLanternData;

    private void readIvoryLantern() {
        String data = ivoryLanternData;
        String ivoryLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryLanternFile = new File(ivoryLanternRoot + data);
            FileInputStream ivoryLanternStream = null;
            InputStreamReader ivoryLanternStreamReader = null;
            BufferedReader ivoryLanternReader = null;
            if (ivoryLanternFile.exists() && ivoryLanternFile.isFile()) {
                try {
                    ivoryLanternStream = new FileInputStream(ivoryLanternFile);
                    ivoryLanternStreamReader = new InputStreamReader(ivoryLanternStream, "UTF-8");
                    ivoryLanternReader = new BufferedReader(ivoryLanternStreamReader);
                    System.out.println(ivoryLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_IvoryLanternSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryLanternReader != null) {
                            ivoryLanternReader.close();
                        }
                        if (ivoryLanternStreamReader != null) {
                            ivoryLanternStreamReader.close();
                        }
                        if (ivoryLanternStream != null) {
                            ivoryLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_IvoryLanternSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryLantern() {
        String data;
        data = "foo";
        ivoryLanternData = data;
        readIvoryLantern();
    }
}

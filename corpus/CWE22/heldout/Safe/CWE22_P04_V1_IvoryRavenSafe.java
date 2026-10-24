import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_IvoryRavenSafe {

    private String locateIvoryRaven() {
        String data;
        data = "foo";
        return data;
    }

    public void openIvoryRaven() {
        String data = locateIvoryRaven();
        String ivoryRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryRavenFile = new File(ivoryRavenRoot + data);
            FileInputStream ivoryRavenStream = null;
            InputStreamReader ivoryRavenStreamReader = null;
            BufferedReader ivoryRavenReader = null;
            if (ivoryRavenFile.exists() && ivoryRavenFile.isFile()) {
                try {
                    ivoryRavenStream = new FileInputStream(ivoryRavenFile);
                    ivoryRavenStreamReader = new InputStreamReader(ivoryRavenStream, "UTF-8");
                    ivoryRavenReader = new BufferedReader(ivoryRavenStreamReader);
                    System.out.println(ivoryRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_IvoryRavenSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryRavenReader != null) {
                            ivoryRavenReader.close();
                        }
                        if (ivoryRavenStreamReader != null) {
                            ivoryRavenStreamReader.close();
                        }
                        if (ivoryRavenStream != null) {
                            ivoryRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_IvoryRavenSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

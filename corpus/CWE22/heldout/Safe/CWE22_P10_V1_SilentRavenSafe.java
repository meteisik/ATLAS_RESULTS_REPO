import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SilentRavenSafe {
    public static String data;

    public void openSilentRaven() {
        data = "foo";
        (new CWE22_P10_V1_SilentRavenSafeSink()).readSilentRaven();
    }
}

class CWE22_P10_V1_SilentRavenSafeSink {
    public void readSilentRaven() {
        String data = CWE22_P10_V1_SilentRavenSafe.data;
        String silentRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File silentRavenFile = new File(silentRavenRoot + data);
            FileInputStream silentRavenStream = null;
            InputStreamReader silentRavenStreamReader = null;
            BufferedReader silentRavenReader = null;
            if (silentRavenFile.exists() && silentRavenFile.isFile()) {
                try {
                    silentRavenStream = new FileInputStream(silentRavenFile);
                    silentRavenStreamReader = new InputStreamReader(silentRavenStream, "UTF-8");
                    silentRavenReader = new BufferedReader(silentRavenStreamReader);
                    System.out.println(silentRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_SilentRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentRavenReader != null) {
                            silentRavenReader.close();
                        }
                        if (silentRavenStreamReader != null) {
                            silentRavenStreamReader.close();
                        }
                        if (silentRavenStream != null) {
                            silentRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_SilentRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

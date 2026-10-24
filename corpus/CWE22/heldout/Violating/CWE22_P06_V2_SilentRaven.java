import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SilentRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void openSilentRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_RAVEN_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_SilentRavenSink()).readSilentRaven(data);
    }
}

class CWE22_P06_V2_SilentRavenSink {
    public void readSilentRaven(String data) {
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
                    Logger.getLogger("CWE22_P06_V2_SilentRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P06_V2_SilentRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

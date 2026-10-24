import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SilentRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSilentRaven() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_RAVEN_PATH");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SilentRavenSink()).readSilentRaven(dataArray);
    }
}

class CWE22_P08_V2_SilentRavenSink {
    public void readSilentRaven(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SilentRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SilentRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

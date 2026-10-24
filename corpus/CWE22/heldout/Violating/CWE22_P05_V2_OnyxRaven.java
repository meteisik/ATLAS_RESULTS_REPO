import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_OnyxRaven {
    private String onyxRavenData;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readOnyxRaven() {
        String data = onyxRavenData;
        String onyxRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxRavenFile = new File(onyxRavenRoot + data);
            FileInputStream onyxRavenStream = null;
            InputStreamReader onyxRavenStreamReader = null;
            BufferedReader onyxRavenReader = null;
            if (onyxRavenFile.exists() && onyxRavenFile.isFile()) {
                try {
                    onyxRavenStream = new FileInputStream(onyxRavenFile);
                    onyxRavenStreamReader = new InputStreamReader(onyxRavenStream, "UTF-8");
                    onyxRavenReader = new BufferedReader(onyxRavenStreamReader);
                    System.out.println(onyxRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_OnyxRaven").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxRavenReader != null) {
                            onyxRavenReader.close();
                        }
                        if (onyxRavenStreamReader != null) {
                            onyxRavenStreamReader.close();
                        }
                        if (onyxRavenStream != null) {
                            onyxRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_OnyxRaven").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openOnyxRaven() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_RAVEN_PATH");
        } else {
            data = null;
        }
        onyxRavenData = data;
        readOnyxRaven();
    }
}

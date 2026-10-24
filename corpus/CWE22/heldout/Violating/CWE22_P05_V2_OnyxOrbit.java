import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_OnyxOrbit {
    private String onyxOrbitData;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readOnyxOrbit() {
        String data = onyxOrbitData;
        String onyxOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxOrbitFile = new File(onyxOrbitRoot + data);
            FileInputStream onyxOrbitStream = null;
            InputStreamReader onyxOrbitStreamReader = null;
            BufferedReader onyxOrbitReader = null;
            if (onyxOrbitFile.exists() && onyxOrbitFile.isFile()) {
                try {
                    onyxOrbitStream = new FileInputStream(onyxOrbitFile);
                    onyxOrbitStreamReader = new InputStreamReader(onyxOrbitStream, "UTF-8");
                    onyxOrbitReader = new BufferedReader(onyxOrbitStreamReader);
                    System.out.println(onyxOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_OnyxOrbit").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxOrbitReader != null) {
                            onyxOrbitReader.close();
                        }
                        if (onyxOrbitStreamReader != null) {
                            onyxOrbitStreamReader.close();
                        }
                        if (onyxOrbitStream != null) {
                            onyxOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_OnyxOrbit").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openOnyxOrbit() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_ORBIT_PATH");
        } else {
            data = null;
        }
        onyxOrbitData = data;
        readOnyxOrbit();
    }
}

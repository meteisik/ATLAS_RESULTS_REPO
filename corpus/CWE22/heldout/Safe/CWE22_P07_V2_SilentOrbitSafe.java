import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SilentOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSilentOrbit() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE22_P07_V2_SilentOrbitSafeSource()).locateSilentOrbit();
        } else {
            data = null;
        }
        String silentOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File silentOrbitFile = new File(silentOrbitRoot + data);
            FileInputStream silentOrbitStream = null;
            InputStreamReader silentOrbitStreamReader = null;
            BufferedReader silentOrbitReader = null;
            if (silentOrbitFile.exists() && silentOrbitFile.isFile()) {
                try {
                    silentOrbitStream = new FileInputStream(silentOrbitFile);
                    silentOrbitStreamReader = new InputStreamReader(silentOrbitStream, "UTF-8");
                    silentOrbitReader = new BufferedReader(silentOrbitStreamReader);
                    System.out.println(silentOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SilentOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentOrbitReader != null) {
                            silentOrbitReader.close();
                        }
                        if (silentOrbitStreamReader != null) {
                            silentOrbitStreamReader.close();
                        }
                        if (silentOrbitStream != null) {
                            silentOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SilentOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SilentOrbitSafeSource {
    public String locateSilentOrbit() {
        String data;
        data = "foo";
        return data;
    }
}

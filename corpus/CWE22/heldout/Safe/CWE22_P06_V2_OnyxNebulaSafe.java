import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_OnyxNebulaSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openOnyxNebula() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P06_V2_OnyxNebulaSafeSink()).readOnyxNebula(data);
    }
}

class CWE22_P06_V2_OnyxNebulaSafeSink {
    public void readOnyxNebula(String data) {
        String onyxNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxNebulaFile = new File(onyxNebulaRoot + data);
            FileInputStream onyxNebulaStream = null;
            InputStreamReader onyxNebulaStreamReader = null;
            BufferedReader onyxNebulaReader = null;
            if (onyxNebulaFile.exists() && onyxNebulaFile.isFile()) {
                try {
                    onyxNebulaStream = new FileInputStream(onyxNebulaFile);
                    onyxNebulaStreamReader = new InputStreamReader(onyxNebulaStream, "UTF-8");
                    onyxNebulaReader = new BufferedReader(onyxNebulaStreamReader);
                    System.out.println(onyxNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_OnyxNebulaSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxNebulaReader != null) {
                            onyxNebulaReader.close();
                        }
                        if (onyxNebulaStreamReader != null) {
                            onyxNebulaStreamReader.close();
                        }
                        if (onyxNebulaStream != null) {
                            onyxNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_OnyxNebulaSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SaffronCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSaffronCascade() {
        String data;
        if (IO.staticTrue) {
            data = (new CWE22_P07_V2_SaffronCascadeSafeSource()).locateSaffronCascade();
        } else {
            data = null;
        }
        String saffronCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronCascadeFile = new File(saffronCascadeRoot + data);
            FileInputStream saffronCascadeStream = null;
            InputStreamReader saffronCascadeStreamReader = null;
            BufferedReader saffronCascadeReader = null;
            if (saffronCascadeFile.exists() && saffronCascadeFile.isFile()) {
                try {
                    saffronCascadeStream = new FileInputStream(saffronCascadeFile);
                    saffronCascadeStreamReader = new InputStreamReader(saffronCascadeStream, "UTF-8");
                    saffronCascadeReader = new BufferedReader(saffronCascadeStreamReader);
                    System.out.println(saffronCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SaffronCascadeSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronCascadeReader != null) {
                            saffronCascadeReader.close();
                        }
                        if (saffronCascadeStreamReader != null) {
                            saffronCascadeStreamReader.close();
                        }
                        if (saffronCascadeStream != null) {
                            saffronCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SaffronCascadeSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SaffronCascadeSafeSource {
    public String locateSaffronCascade() {
        String data;
        data = "foo";
        return data;
    }
}

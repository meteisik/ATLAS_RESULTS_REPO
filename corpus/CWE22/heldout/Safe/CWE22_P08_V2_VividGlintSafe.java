import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_VividGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openVividGlint() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_VividGlintSafeSink()).readVividGlint(dataArray);
    }
}

class CWE22_P08_V2_VividGlintSafeSink {
    public void readVividGlint(String[] dataArray) {
        String data = dataArray[2];
        String vividGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File vividGlintFile = new File(vividGlintRoot + data);
            FileInputStream vividGlintStream = null;
            InputStreamReader vividGlintStreamReader = null;
            BufferedReader vividGlintReader = null;
            if (vividGlintFile.exists() && vividGlintFile.isFile()) {
                try {
                    vividGlintStream = new FileInputStream(vividGlintFile);
                    vividGlintStreamReader = new InputStreamReader(vividGlintStream, "UTF-8");
                    vividGlintReader = new BufferedReader(vividGlintStreamReader);
                    System.out.println(vividGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V2_VividGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividGlintReader != null) {
                            vividGlintReader.close();
                        }
                        if (vividGlintStreamReader != null) {
                            vividGlintStreamReader.close();
                        }
                        if (vividGlintStream != null) {
                            vividGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V2_VividGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

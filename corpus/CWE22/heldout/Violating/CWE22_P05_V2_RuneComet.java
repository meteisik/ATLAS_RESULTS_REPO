import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_RuneComet {
    private String runeCometData;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readRuneComet() {
        String data = runeCometData;
        String runeCometRoot = "/home/user/uploads/";
        if (data != null) {
            File runeCometFile = new File(runeCometRoot + data);
            FileInputStream runeCometStream = null;
            InputStreamReader runeCometStreamReader = null;
            BufferedReader runeCometReader = null;
            if (runeCometFile.exists() && runeCometFile.isFile()) {
                try {
                    runeCometStream = new FileInputStream(runeCometFile);
                    runeCometStreamReader = new InputStreamReader(runeCometStream, "UTF-8");
                    runeCometReader = new BufferedReader(runeCometStreamReader);
                    System.out.println(runeCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_RuneComet").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeCometReader != null) {
                            runeCometReader.close();
                        }
                        if (runeCometStreamReader != null) {
                            runeCometStreamReader.close();
                        }
                        if (runeCometStream != null) {
                            runeCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_RuneComet").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openRuneComet() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_COMET_PATH");
        } else {
            data = null;
        }
        runeCometData = data;
        readRuneComet();
    }
}

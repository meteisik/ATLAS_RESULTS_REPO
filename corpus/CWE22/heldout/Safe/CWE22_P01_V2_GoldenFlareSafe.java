import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openGoldenFlare() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String goldenFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenFlareFile = new File(goldenFlareRoot + data);
            FileInputStream goldenFlareStream = null;
            InputStreamReader goldenFlareStreamReader = null;
            BufferedReader goldenFlareReader = null;
            if (goldenFlareFile.exists() && goldenFlareFile.isFile()) {
                try {
                    goldenFlareStream = new FileInputStream(goldenFlareFile);
                    goldenFlareStreamReader = new InputStreamReader(goldenFlareStream, "UTF-8");
                    goldenFlareReader = new BufferedReader(goldenFlareStreamReader);
                    System.out.println(goldenFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_GoldenFlareSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenFlareReader != null) {
                            goldenFlareReader.close();
                        }
                        if (goldenFlareStreamReader != null) {
                            goldenFlareStreamReader.close();
                        }
                        if (goldenFlareStream != null) {
                            goldenFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_GoldenFlareSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

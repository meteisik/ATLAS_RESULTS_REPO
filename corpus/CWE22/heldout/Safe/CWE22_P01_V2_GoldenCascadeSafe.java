import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openGoldenCascade() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String goldenCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenCascadeFile = new File(goldenCascadeRoot + data);
            FileInputStream goldenCascadeStream = null;
            InputStreamReader goldenCascadeStreamReader = null;
            BufferedReader goldenCascadeReader = null;
            if (goldenCascadeFile.exists() && goldenCascadeFile.isFile()) {
                try {
                    goldenCascadeStream = new FileInputStream(goldenCascadeFile);
                    goldenCascadeStreamReader = new InputStreamReader(goldenCascadeStream, "UTF-8");
                    goldenCascadeReader = new BufferedReader(goldenCascadeStreamReader);
                    System.out.println(goldenCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_GoldenCascadeSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenCascadeReader != null) {
                            goldenCascadeReader.close();
                        }
                        if (goldenCascadeStreamReader != null) {
                            goldenCascadeStreamReader.close();
                        }
                        if (goldenCascadeStream != null) {
                            goldenCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_GoldenCascadeSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

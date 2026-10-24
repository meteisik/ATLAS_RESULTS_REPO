import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_JadeSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readJadeSundial(String data) {
        String jadeSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeSundialFile = new File(jadeSundialRoot + data);
            FileInputStream jadeSundialStream = null;
            InputStreamReader jadeSundialStreamReader = null;
            BufferedReader jadeSundialReader = null;
            if (jadeSundialFile.exists() && jadeSundialFile.isFile()) {
                try {
                    jadeSundialStream = new FileInputStream(jadeSundialFile);
                    jadeSundialStreamReader = new InputStreamReader(jadeSundialStream, "UTF-8");
                    jadeSundialReader = new BufferedReader(jadeSundialStreamReader);
                    System.out.println(jadeSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_JadeSundial").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeSundialReader != null) {
                            jadeSundialReader.close();
                        }
                        if (jadeSundialStreamReader != null) {
                            jadeSundialStreamReader.close();
                        }
                        if (jadeSundialStream != null) {
                            jadeSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_JadeSundial").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openJadeSundial() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("JADE_SUNDIAL_PATH");
        } else {
            data = null;
        }
        readJadeSundial(data);
    }
}

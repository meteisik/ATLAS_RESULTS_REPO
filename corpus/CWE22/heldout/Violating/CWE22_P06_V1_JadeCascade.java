import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadeCascade {

    public void openJadeCascade() {
        String data;
        data = System.getenv("JADE_CASCADE_PATH");
        (new CWE22_P06_V1_JadeCascadeSink()).readJadeCascade(data);
    }
}

class CWE22_P06_V1_JadeCascadeSink {
    public void readJadeCascade(String data) {
        String jadeCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeCascadeFile = new File(jadeCascadeRoot + data);
            FileInputStream jadeCascadeStream = null;
            InputStreamReader jadeCascadeStreamReader = null;
            BufferedReader jadeCascadeReader = null;
            if (jadeCascadeFile.exists() && jadeCascadeFile.isFile()) {
                try {
                    jadeCascadeStream = new FileInputStream(jadeCascadeFile);
                    jadeCascadeStreamReader = new InputStreamReader(jadeCascadeStream, "UTF-8");
                    jadeCascadeReader = new BufferedReader(jadeCascadeStreamReader);
                    System.out.println(jadeCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_JadeCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeCascadeReader != null) {
                            jadeCascadeReader.close();
                        }
                        if (jadeCascadeStreamReader != null) {
                            jadeCascadeStreamReader.close();
                        }
                        if (jadeCascadeStream != null) {
                            jadeCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_JadeCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

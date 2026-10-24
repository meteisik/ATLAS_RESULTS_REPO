import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P06_V1_JadeCascade {

    public void openJadeCascade() throws IOException {
        String data;
        data = System.getenv("JADE_CASCADE_PATH");
        (new CWE22_P06_V1_JadeCascadeSink()).readJadeCascade(data);
    }
}

class CWE22_P06_V1_JadeCascadeSink {
    public void readJadeCascade(String data) throws IOException {
        String jadeCascadeRoot = "/home/user/uploads/";
        File jadeCascadeFile = new File(jadeCascadeRoot + data);
        FileInputStream jadeCascadeStream = new FileInputStream(jadeCascadeFile);
        jadeCascadeStream.close();
    }
}

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VelvetFlare {

    public void runVelvetFlare() throws SQLException {
        String data;
        data = System.getenv("VELVET_FLARE_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VelvetFlareSink()).queryVelvetFlare(dataHashMap);
    }
}

class CWE89_P11_V1_VelvetFlareSink {
    public void queryVelvetFlare(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        Statement velvetFlareStatement = null;
        ResultSet velvetFlareRows = null;
        try {
            velvetFlareStatement = velvetFlareConnection.createStatement();
            velvetFlareRows = velvetFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetFlareRows.getRow());
        } finally {
            if (velvetFlareRows != null) {
                velvetFlareRows.close();
            }
            if (velvetFlareStatement != null) {
                velvetFlareStatement.close();
            }
            velvetFlareConnection.close();
        }
    }
}

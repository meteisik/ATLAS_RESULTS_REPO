import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrFlare {

    public void runZephyrFlare() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_FLARE_FILTER");
        CWE89_P12_V1_ZephyrFlareBase baseObject = new CWE89_P12_V1_ZephyrFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrFlareBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrFlareSink extends CWE89_P12_V1_ZephyrFlareBase {
    public void action(String data) throws SQLException {
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        Statement zephyrFlareStatement = null;
        ResultSet zephyrFlareRows = null;
        try {
            zephyrFlareStatement = zephyrFlareConnection.createStatement();
            zephyrFlareRows = zephyrFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrFlareRows.getRow());
        } finally {
            if (zephyrFlareRows != null) {
                zephyrFlareRows.close();
            }
            if (zephyrFlareStatement != null) {
                zephyrFlareStatement.close();
            }
            zephyrFlareConnection.close();
        }
    }
}

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrFlareSafe {

    public void runZephyrFlare() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrFlareSafeBase baseObject = new CWE89_P12_V1_ZephyrFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrFlareSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrFlareSafeSink extends CWE89_P12_V1_ZephyrFlareSafeBase {
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

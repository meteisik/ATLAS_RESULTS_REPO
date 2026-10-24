import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrQuartzSafe {

    public void runZephyrQuartz() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrQuartzSafeBase baseObject = new CWE89_P12_V1_ZephyrQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrQuartzSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrQuartzSafeSink extends CWE89_P12_V1_ZephyrQuartzSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        Statement zephyrQuartzStatement = null;
        ResultSet zephyrQuartzRows = null;
        try {
            zephyrQuartzStatement = zephyrQuartzConnection.createStatement();
            zephyrQuartzRows = zephyrQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrQuartzRows.getRow());
        } finally {
            if (zephyrQuartzRows != null) {
                zephyrQuartzRows.close();
            }
            if (zephyrQuartzStatement != null) {
                zephyrQuartzStatement.close();
            }
            zephyrQuartzConnection.close();
        }
    }
}

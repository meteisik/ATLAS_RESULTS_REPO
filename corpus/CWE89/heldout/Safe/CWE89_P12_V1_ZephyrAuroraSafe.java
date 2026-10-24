import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrAuroraSafe {

    public void runZephyrAurora() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrAuroraSafeBase baseObject = new CWE89_P12_V1_ZephyrAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrAuroraSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrAuroraSafeSink extends CWE89_P12_V1_ZephyrAuroraSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        Statement zephyrAuroraStatement = null;
        ResultSet zephyrAuroraRows = null;
        try {
            zephyrAuroraStatement = zephyrAuroraConnection.createStatement();
            zephyrAuroraRows = zephyrAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrAuroraRows.getRow());
        } finally {
            if (zephyrAuroraRows != null) {
                zephyrAuroraRows.close();
            }
            if (zephyrAuroraStatement != null) {
                zephyrAuroraStatement.close();
            }
            zephyrAuroraConnection.close();
        }
    }
}

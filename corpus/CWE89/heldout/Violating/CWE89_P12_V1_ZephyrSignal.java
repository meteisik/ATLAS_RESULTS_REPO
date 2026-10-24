import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrSignal {

    public void runZephyrSignal() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_FILTER");
        CWE89_P12_V1_ZephyrSignalBase baseObject = new CWE89_P12_V1_ZephyrSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrSignalBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrSignalSink extends CWE89_P12_V1_ZephyrSignalBase {
    public void action(String data) throws SQLException {
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        Statement zephyrSignalStatement = null;
        ResultSet zephyrSignalRows = null;
        try {
            zephyrSignalStatement = zephyrSignalConnection.createStatement();
            zephyrSignalRows = zephyrSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrSignalRows.getRow());
        } finally {
            if (zephyrSignalRows != null) {
                zephyrSignalRows.close();
            }
            if (zephyrSignalStatement != null) {
                zephyrSignalStatement.close();
            }
            zephyrSignalConnection.close();
        }
    }
}

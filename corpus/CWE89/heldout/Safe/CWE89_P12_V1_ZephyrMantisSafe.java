import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrMantisSafe {

    public void runZephyrMantis() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrMantisSafeBase baseObject = new CWE89_P12_V1_ZephyrMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrMantisSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrMantisSafeSink extends CWE89_P12_V1_ZephyrMantisSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        Statement zephyrMantisStatement = null;
        ResultSet zephyrMantisRows = null;
        try {
            zephyrMantisStatement = zephyrMantisConnection.createStatement();
            zephyrMantisRows = zephyrMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrMantisRows.getRow());
        } finally {
            if (zephyrMantisRows != null) {
                zephyrMantisRows.close();
            }
            if (zephyrMantisStatement != null) {
                zephyrMantisStatement.close();
            }
            zephyrMantisConnection.close();
        }
    }
}

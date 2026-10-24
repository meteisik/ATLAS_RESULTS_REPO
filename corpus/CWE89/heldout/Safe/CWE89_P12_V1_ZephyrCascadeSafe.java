import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrCascadeSafe {

    public void runZephyrCascade() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrCascadeSafeBase baseObject = new CWE89_P12_V1_ZephyrCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrCascadeSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrCascadeSafeSink extends CWE89_P12_V1_ZephyrCascadeSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        Statement zephyrCascadeStatement = null;
        ResultSet zephyrCascadeRows = null;
        try {
            zephyrCascadeStatement = zephyrCascadeConnection.createStatement();
            zephyrCascadeRows = zephyrCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCascadeRows.getRow());
        } finally {
            if (zephyrCascadeRows != null) {
                zephyrCascadeRows.close();
            }
            if (zephyrCascadeStatement != null) {
                zephyrCascadeStatement.close();
            }
            zephyrCascadeConnection.close();
        }
    }
}
